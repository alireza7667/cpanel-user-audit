# 🔎 cPanel User Audit

ابزار حرفه‌ای و فقط‌خواندنی برای بررسی مشکلات کاربران cPanel، مصرف منابع، ترافیک، ربات‌ها و وضعیت WordPress روی سرورهای cPanel / CloudLinux / LiteSpeed / Apache.

## 🚀 اجرا

با دسترسی `root` اجرا کنید:

```bash
curl -fsSL https://raw.githubusercontent.com/alireza7667/cpanel-user-audit/main/cpanel-user-audit.sh | bash -s -- CPANEL_USERNAME
```

به‌جای `CPANEL_USERNAME` نام واقعی کاربر cPanel را وارد کنید:

```bash
curl -fsSL https://raw.githubusercontent.com/alireza7667/cpanel-user-audit/main/cpanel-user-audit.sh | bash -s -- abmtgcom
```

## ✅ بررسی‌های انجام‌شده

- 🌐 شناسایی دامنه‌ها و مسیرهای سایت
- 🚦 بررسی وضعیت HTTP، Cache و Headerها
- 🕵️ شناسایی IPهای پرترافیک و درخواست‌های مشکوک
- 🤖 تحلیل ربات‌ها و User-Agentها
- 💾 بررسی Disk، Quota و Inode
- ⚡ بررسی CPU، RAM، پردازش‌ها و محدودیت‌های CloudLinux
- 🐘 بررسی PHP، PHP-FPM، LSAPI و OPcache
- 🧩 بررسی WordPress، افزونه‌ها، قالب‌ها و یکپارچگی هسته
- 👤 بررسی کاربران Administrator و رویدادهای WP-Cron
- 📧 بررسی صف ایمیل Exim
- 📋 بررسی Cron Jobها
- 🛡️ شناسایی فایل‌های PHP مشکوک و فایل‌های PHP داخل Uploads
- 🗄️ بررسی وضعیت MySQL / MariaDB
- ☁️ بررسی رویدادهای امنیتی Cloudflare در صورت تنظیم API

## 🔐 ویژگی‌های امنیتی

- فقط گزارش‌گیری و بدون تغییر در سایت یا تنظیمات
- مناسب برای عیب‌یابی مشکلات مصرف منابع و ترافیک
- اجرای مستقیم از GitHub و همیشه در دسترس
- نمایش خلاصهٔ نهایی با سطح‌بندی `HIGH`، `MEDIUM` و `LOW`

## ☁️ بررسی Cloudflare

برای فعال‌کردن بخش Cloudflare:

```bash
CF_API_TOKEN="YOUR_TOKEN" CF_ZONE_ID="YOUR_ZONE_ID" \
curl -fsSL https://raw.githubusercontent.com/alireza7667/cpanel-user-audit/main/cpanel-user-audit.sh \
| bash -s -- CPANEL_USERNAME
```

## ⚠️ نکات مهم

- اسکریپت باید با دسترسی `root` اجرا شود.
- نام کاربر cPanel الزامی است.
- فقط روی سرورهایی اجرا کنید که مالک یا مدیر آن هستید.
- خروجی اسکریپت ممکن است شامل اطلاعات حساس سرور باشد؛ آن را عمومی منتشر نکنید.

---

# 🔎 cPanel User Audit

A read-only diagnostic tool for investigating cPanel user issues, resource usage, traffic, bots, and WordPress health on cPanel, CloudLinux, LiteSpeed, and Apache servers.

## 🚀 Usage

Run as `root`:

```bash
curl -fsSL https://raw.githubusercontent.com/alireza7667/cpanel-user-audit/main/cpanel-user-audit.sh | bash -s -- CPANEL_USERNAME
```

Replace `CPANEL_USERNAME` with the actual cPanel username:

```bash
curl -fsSL https://raw.githubusercontent.com/alireza7667/cpanel-user-audit/main/cpanel-user-audit.sh | bash -s -- abmtgcom
```

## ✅ What It Checks

- 🌐 Domains and document roots
- 🚦 HTTP status, cache, and response headers
- 🕵️ Top source IPs and suspicious requests
- 🤖 Bots and User-Agent activity
- 💾 Disk usage, quota, and inode pressure
- ⚡ CPU, memory, processes, and CloudLinux limits
- 🐘 PHP, PHP-FPM, LSAPI, and OPcache
- 🧩 WordPress core, plugins, themes, and integrity
- 👤 WordPress administrators and WP-Cron events
- 📧 Exim mail queue
- 📋 Cron jobs and references
- 🛡️ Suspicious PHP files and PHP files inside uploads
- 🗄️ MySQL / MariaDB activity
- ☁️ Cloudflare security events when API variables are provided

## 🔐 Safety

- Read-only diagnostic operation
- Does not modify websites or server configuration
- Useful for finding traffic, resource, and security problems
- Provides a final summary with `HIGH`, `MEDIUM`, and `LOW` findings

## ⚠️ Notes

- Root access is required.
- A valid cPanel username is required.
- Use only on servers you own or administer.
- Audit output may contain sensitive server information; do not share it publicly.
