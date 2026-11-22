# Questionnaire avec pass (version en ligne, gratuite, sans serveur)

Pages statiques (GitHub Pages) + base de données Supabase. Aucun serveur à faire tourner, ton PC peut être éteint.

- `index.html` : page des participants (lien à partager)
- `admin.html` : administration (mot de passe)
- `pass.html?c=CODE` : page affichée au scan du QR code (valable, périmé ou inconnu)
- `schema.sql` : la base (tables + fonctions : correction, codes, expiration à 6 mois…)
- `config.js` : l'adresse et la clé publique de ton projet Supabase
- `api.js`, `pdf.js` : appels à la base, pass PDF avec QR code (fabriqué dans le navigateur)

## Mise en ligne, étape par étape

### 1. Créer le projet Supabase (gratuit)
1. Va sur https://supabase.com, crée un compte, puis **New project** (offre Free).
2. Choisis un nom et un mot de passe de base de données (garde-le, mais il ne sert pas dans le site), puis une région en Europe.

### 2. Installer la base
1. Dans Supabase : **SQL Editor** > **New query**.
2. Colle tout le contenu de `schema.sql`, puis **Run**.
3. Définis ton mot de passe admin en lançant cette requête (remplace par TON mot de passe) :

```sql
insert into settings (key, value)
values ('admin_hash', extensions.crypt('MON-MOT-DE-PASSE-ADMIN', extensions.gen_salt('bf')))
on conflict (key) do update set value = excluded.value;
```

(Pour le changer plus tard, relance la même requête avec un autre mot de passe. Le mot de passe n'est jamais stocké en clair.)

### 3. Relier le site à la base
1. Dans Supabase : **Project Settings** > **API** (ou **API Keys**).
2. Copie l'**URL du projet** et la clé **anon** (ou **publishable**). Cette clé est faite pour être publique.
3. Colle-les dans `config.js`. N'utilise jamais la clé `service_role`.

### 4. Publier les pages sur GitHub Pages
1. Mets ces fichiers dans un dépôt GitHub (public : GitHub Pages gratuit l'exige).
2. Dépôt > **Settings** > **Pages** > Source : **Deploy from a branch**, branche `main`, dossier `/ (root)`.
3. Au bout d'une minute, le site est sur `https://TON-COMPTE.github.io/NOM-DU-DEPOT/` :
   - participants : l'adresse ci-dessus
   - admin : `…/admin.html`

Alternative si tu veux un dépôt privé : Cloudflare Pages ou Netlify (gratuits) acceptent aussi les dépôts privés.

## À savoir
- **Vidéos** : seuls les liens sont acceptés (YouTube, ou lien direct vers un .mp4). L'envoi de fichiers depuis le PC n'existe pas dans cette version.
- **Sécurité** : les bonnes réponses restent dans la base et ne sont jamais envoyées aux participants. L'admin demande le mot de passe à chaque action ; après 10 essais ratés en 10 minutes, il est bloqué 10 minutes.
- **Plan gratuit Supabase** : le projet se met en pause après environ une semaine sans visite (le premier chargement est alors lent, tu peux le réveiller depuis le tableau de bord). Pense à exporter le tableau en CSV de temps en temps.
- **Pass** : valable 6 mois après la réussite du test. Passé ce délai, il est « périmé » jusqu'à ce que la personne repasse le test.
