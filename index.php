<!doctype html>
<html lang="pl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MijAuth 0.4.0 - File + App 2FA</title>
  <style>
    :root {
      --bg: #f6f4ef;
      --card: #fffdf8;
      --ink: #1a1a1a;
      --muted: #5f5f5f;
      --brand: #005f73;
      --brand-2: #ca6702;
      --line: #d9d3c7;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at 10% 10%, #e9f5f7 0, transparent 40%),
        radial-gradient(circle at 90% 80%, #ffe9cf 0, transparent 35%),
        var(--bg);
      line-height: 1.5;
    }

    .wrap {
      max-width: 980px;
      margin: 0 auto;
      padding: 32px 20px 64px;
    }

    .hero {
      background: linear-gradient(130deg, #ffffff 0%, #f7fafb 60%, #fff6ea 100%);
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 28px;
      box-shadow: 0 14px 30px rgba(0, 0, 0, 0.06);
    }

    h1 {
      margin: 0 0 8px;
      font-size: clamp(1.8rem, 4vw, 2.6rem);
      letter-spacing: 0.2px;
    }

    .subtitle {
      margin: 0;
      color: var(--muted);
      max-width: 68ch;
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 14px;
      margin-top: 24px;
    }

    .card {
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 16px;
    }

    .card h2 {
      margin-top: 0;
      font-size: 1.05rem;
    }

    .badge {
      display: inline-block;
      font-size: 0.8rem;
      font-weight: 600;
      border: 1px solid color-mix(in srgb, var(--brand), #ffffff 60%);
      color: var(--brand);
      background: #e7f6f8;
      padding: 0.2rem 0.5rem;
      border-radius: 999px;
      margin-bottom: 10px;
    }

    code {
      background: #f0ece3;
      padding: 0.12rem 0.35rem;
      border-radius: 4px;
    }

    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 22px;
    }

    .btn {
      display: inline-block;
      text-decoration: none;
      border-radius: 10px;
      padding: 10px 14px;
      font-weight: 600;
      border: 1px solid transparent;
    }

    .btn-primary {
      background: var(--brand);
      color: #fff;
    }

    .btn-secondary {
      background: #fff;
      color: var(--brand-2);
      border-color: #e7cfb0;
    }

    .note {
      margin-top: 18px;
      color: var(--muted);
      font-size: 0.92rem;
    }

    @media (max-width: 600px) {
      .hero { padding: 20px; }
      .wrap { padding: 20px 14px 42px; }
    }
  </style>
</head>
<body>
  <main class="wrap">
    <section class="hero">
      <span class="badge">MijAuth 0.4.0</span>
      <h1>File-Based 2FA + kody z aplikacji TOTP</h1>
      <p class="subtitle">
        Aktualizacja dodaje możliwość łączenia pliku <code>.mijauth</code> z kodami 2FA z aplikacji,
        walidację czasu życia pliku (TTL) oraz bezpieczniejsze podejście do fingerprintu urządzenia.
      </p>

      <div class="grid">
        <article class="card">
          <h2>Nowości bezpieczeństwa</h2>
          <ul>
            <li>Domyślny sekret TOTP: 32 znaki Base32 (160 bitów)</li>
            <li>Weryfikacja TTL dla <code>created_at</code> (domyślnie 30 dni)</li>
            <li>Rate limiting prób TOTP w <code>AuthManager</code></li>
          </ul>
        </article>

        <article class="card">
          <h2>Flow logowania</h2>
          <ol>
            <li>Hasło</li>
            <li>Plik <code>.mijauth</code></li>
            <li>Opcjonalny kod TOTP z aplikacji</li>
          </ol>
        </article>

        <article class="card">
          <h2>Przykłady</h2>
          <p>Zaktualizowane demo dla:</p>
          <ul>
            <li>PHP</li>
            <li>Node.js</li>
            <li>Python</li>
          </ul>
        </article>
      </div>

      <div class="actions">
        <a class="btn btn-primary" href="README.md">Dokumentacja (README)</a>
        <a class="btn btn-secondary" href="examples/">Katalog przykładów</a>
      </div>

      <p class="note">
        Uwaga: GitHub Pages renderuje ten plik jako statyczny dokument. Kod PHP nie jest wykonywany po stronie serwera.
      </p>
    </section>
  </main>
</body>
</html>
