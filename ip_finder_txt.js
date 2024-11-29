const {spawn} = require('child_process');
const {exec} = require('child_process');
const fs = require('fs');
const {download} = require('wget-improved');

// آرایه برای ذخیره IP‌ها به همراه زمان
let ipArray = [];

// آرایه برای ذخیره IPهایی که قبلاً نمایش داده شده‌اند
let shownIPs = [];

// آدرس فایل تکست
const fileUrl = 'http://ips.xdvpn.xyz/ips.txt'; // لینک فایل تکست
const localFilePath = '/tmp/ips.txt'; // مسیر ذخیره فایل دانلود شده

// تابع برای دانلود فایل IP‌ها
function downloadIPFile(callback) {
    download(fileUrl, localFilePath, (error) => {
        if (error) {
            console.error('Error downloading IP file:', error);
            return callback(error, []);
        }

        // خواندن فایل پس از دانلود
        fs.readFile(localFilePath, 'utf8', (err, data) => {
            if (err) {
                console.error('Error reading IP file:', err);
                return callback(err, []);
            }

            // جدا کردن IP‌ها با توجه به کاما
            const ips = data.split(',').map(ip => ip.trim());
            callback(null, ips);
        });
    });
}

// تابع برای اضافه کردن IP همراه با زمان به آرایه
function saveIP(ip) {
    const currentTime = Date.now(); // زمان لحظه‌ای به میلی‌ثانیه
    // چک کردن اینکه آیا IP قبلاً اضافه شده است یا خیر
    const existingIP = ipArray.find(entry => entry.ip === ip);
    if (!existingIP) {
        ipArray.push({ip: ip, timestamp: currentTime});
        console.log(`IP Added: ${ip} at ${new Date(currentTime).toISOString()}`);
    }
}

// تابع برای بدست آوردن IP‌هایی که بیشتر از 2 دقیقه از زمان ذخیره آنها گذشته
function getOldIPs() {
    const currentTime = Date.now();
    // فیلتر کردن IP‌هایی که بیشتر از 2 دقیقه از زمان ذخیره آنها گذشته است
    const oldIPs = ipArray.filter(entry => currentTime - entry.timestamp > 2 * 60 * 1000); // 2 دقیقه
    return oldIPs;
}

// تابع برای نمایش IPهایی که بیشتر از 2 دقیقه از ذخیره‌شدن آنها گذشته است و اضافه نشده‌اند به shownIPs
function showNewOldIPs() {
    const oldIPs = getOldIPs();
    const newOldIPs = oldIPs.filter(entry => !shownIPs.includes(entry.ip));

    if (newOldIPs.length > 0) {
        console.log('New IPs older than 2 minutes:', newOldIPs);

        // دانلود فایل و مقایسه با IP‌های قدیمی
        downloadIPFile((err, fileIPs) => {
            if (err) return;

            // فیلتر کردن IP‌هایی که در فایل تکست نیستند
            const notInFile = newOldIPs.filter(entry => !fileIPs.includes(entry.ip));
            const notInFileIPs = notInFile.map(entry => entry.ip);  // استخراج ای‌پی‌ها
            const ipList = notInFileIPs.join(',');  // ای‌پی‌ها را با کاما جدا کنید

            // ساخت دستور iptables
            const iptablesCommand = `sudo iptables -I INPUT -s ${ipList} -j DROP`;
            console.log(iptablesCommand);

            // اجرای دستور iptables
            exec(iptablesCommand, (error, stdout, stderr) => {
                if (error) {
                    console.error(`exec error: ${error}`);
                    return;
                }
                if (stderr) {
                    console.error(`stderr: ${stderr}`);
                    return;
                }
                console.log(`stdout: ${stdout}`);
            });

            console.log('IPs not found in file:', notInFile);
        });

        // اضافه کردن IP‌های جدید به shownIPs
        newOldIPs.forEach(entry => shownIPs.push(entry.ip));
    }
}

// اجرای دستور journalctl برای گرفتن لاگ‌ها
const journalctl = spawn('journalctl', ['--follow', '-u', 'stunnel4.service']);

// خواندن خروجی دستور journalctl
journalctl.stdout.on('data', (data) => {
    const log = data.toString();
    // جستجوی آدرس‌های IPv4 در لاگ
    const regex = /([0-9]{1,3}\.){3}[0-9]{1,3}/g;
    const ips = log.match(regex);

    if (ips) {
        ips.forEach((ip) => saveIP(ip));
    }
});

// نمایش خطاهای احتمالی
journalctl.stderr.on('data', (data) => {
    console.error(`stderr: ${data}`);
});

// پایان پروسه
journalctl.on('close', (code) => {
    console.log(`journalctl process exited with code ${code}`);
});

// نمایش IPهای قدیمی که بیشتر از 2 دقیقه گذشته است و هنوز نمایش داده نشده‌اند
setInterval(() => {
    showNewOldIPs();
}, 10 * 60 * 1000); // هر 2 دقیقه یکبار
