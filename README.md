# Donor / Trust Quota Application Preparation — Cloudflare Pages project

## Contents
- `index.html`: black-and-white homepage, application wizard, instructions and privacy policy in one responsive page.
- `functions/api/application/draft.js`: creates a server-side draft and access token.
- `functions/api/application/page.js`: stores individual validated/consented page data.
- `functions/api/application/submit.js`: finalizes the preparation set only when required pages have been saved.
- `schema.sql`: D1 database schema.

## Important limits and accuracy
This is an independent preparation tool, not an official WBMCC portal. The generated application/page/submission references are tracking IDs for this service only. The final submit endpoint records completion in this app; it does not submit to WBMCC. This starter does not upload file bytes: file inputs track file names only. Do not collect real applicant data until access, retention, deletion, security, legal and privacy requirements have been reviewed.

## Deploy to Cloudflare Pages
1. Upload the contents of this folder to the root of a GitHub repository connected to Cloudflare Pages. `index.html` must be at repository root.
2. In Cloudflare dashboard, create a D1 database (e.g. `quota-preparation-db`).
3. Run `schema.sql` against that D1 database using the D1 console or Wrangler.
4. In Pages project → Settings → Functions → D1 database bindings, add binding name `APP_DB` and select your database.
5. Redeploy. Cloudflare Pages Functions will expose:
   - `POST /api/application/draft`
   - `POST /api/application/page`
   - `POST /api/application/submit`
6. Test using fictional data first. If the API is not deployed, the browser will still save locally but server save/final submit will report an API error.

## Storage and security
- Draft form data is saved locally in browser localStorage for convenience.
- Server-side data is stored in D1 once the binding is configured.
- The draft API issues a random access token; the client stores it locally and sends it in `X-Application-Token`. The server stores only its SHA-256 hash.
- Treat the D1 database as sensitive. Configure access permissions, backups, retention/deletion policies, and monitor abuse before production use.
- This version does not include an admin dashboard, email/SMS notifications, malware scanning, or file upload storage.
- File names can be personal data. Do not upload sensitive documents to unverified recipients.
- No official affiliation or authorization is claimed. Remove any claims of authorization unless independently substantiated.


## Private admin page
- Admin page path: `/private/index.html`.
- Add a Cloudflare Pages secret named `ADMIN_SECRET` using a strong, newly generated password. Do not put the password in HTML or Git.
- The admin endpoint is `GET /api/admin/applications`; it requires `Authorization: Bearer <ADMIN_SECRET>` and returns references/status only.
- Additionally protect `/private/*` using Cloudflare Access. The HTML page is not itself a security boundary.
- Do not use the token strings posted in chat as production credentials. Treat them as exposed and replace them. Never put reusable access tokens in public HTML or commit them to a public repository.
