# WP Auth via Custom API (ProxiCE)

Authenticate WordPress users against an **external API** instead of the local password system.  
If the remote login succeeds, the plugin will find or create a matching WordPress user and log them in automatically.

---

## 🔧 Features

- Replace native WP password authentication with your own REST API
- Auto-create local users on first login (optional)
  - Update user login (email) with api username (membership card id)
  - Sync user metadata at login (email, name, mobile)
- Map remote profile fields (email, name, company, etc.)
- Sync roles based on company name
- Built-in settings page under **Settings → External Auth**

---

## 🧩 Requirements

- WordPress **5.8+**
- PHP **7.4+**
- External API must expose endpoints compatible with:
  - `POST /login_v3`
  - `GET /me`
  - `GET /company/:id`
  - and return JSON objects (see examples below)

---

## Notes

### Update .pot file

```bash
wp i18n make-pot . languages/wp-auth-custom-api-proxice.pot --slug=wp-auth-custom-api-proxice
```
