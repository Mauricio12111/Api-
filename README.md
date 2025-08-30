# API GamerHubX

![c7c6f4ba-02b1-49ba-b60d-772fc19b1087](https://github.com/user-attachments/assets/dc42fb22-70b1-48c4-84a9-0bd2ea686213)

Ce projet est une API Node.js conçue pour gérer l'authentification (e-mail/mot de passe, Google OAuth), les sessions utilisateur, les clés API et les transactions financières. Le serveur utilise une base de données PostgreSQL et est optimisé pour le déploiement sur la plateforme Render.

---

### 💻 Technologies Utilisées

* **Node.js & Express** : Environnement d'exécution et framework web pour le serveur.
* **PostgreSQL & `pg`** : Système de gestion de base de données relationnelle et son client Node.js.
* **`bcrypt`** : Hachage sécurisé des mots de passe.
* **`jsonwebtoken` (JWT)** : Création et validation des tokens d'authentification.
* **`google-auth-library`** : Intégration de l'authentification via Google OAuth.
* **`express-rate-limit`** : Protection contre les attaques par force brute et les abus.
* **`express-validator`** : Validation des données entrantes.
* **`dotenv`** : Gestion des variables d'environnement (recommandé).

---

### ⚙️ Configuration et Déploiement

Pour déployer cette API sur Render, suivez ces étapes :

#### 1. Configuration de la base de données PostgreSQL

Le serveur est configuré pour se connecter à une base de données PostgreSQL. Vous devez vous assurer que votre base de données est accessible et que vous disposez d'une chaîne de connexion valide.

#### 2. Variables d'Environnement

Pour des raisons de sécurité, toutes les informations sensibles (identifiants de base de données, clés secrètes) doivent être stockées dans des variables d'environnement sur Render.
Rendez-vous sur les paramètres de votre service Render et ajoutez les variables suivantes dans la section **Environment** :

* `DATABASE_URL` : Chaîne de connexion complète de votre base de données PostgreSQL.
* `JWT_SECRET` : Une chaîne de caractères longue et aléatoire pour signer les tokens JWT.
* `GOOGLE_CLIENT_ID` : L'ID client de votre application Google OAuth.
* `RATE_LIMIT_WINDOW` : Fenêtre de temps pour la limite de requêtes (en millisecondes).
* `RATE_LIMIT_MAX` : Nombre maximal de requêtes autorisées par fenêtre.
* `PASSWORD_HASH_ROUNDS` : Nombre de tours de salage pour le hachage bcrypt (défaut : 10).
* `API_KEY_LENGTH` : Longueur des clés API générées (défaut : 32).
* `DB_SSL_REJECT_UNAUTHORIZED` : `false` si votre base de données utilise un certificat auto-signé.

#### 3. Déploiement via GitHub

1.  Assurez-vous que votre projet contient les fichiers `index.js` et `package.json` corrects.
2.  Liez votre dépôt GitHub à un nouveau "Web Service" sur Render.
3.  Définissez le **Build Command** sur `npm install`.
4.  Définissez le **Start Command** sur `node index.js`.
5.  Render installera les dépendances et démarrera automatiquement le serveur.

---

### 🚀 Fonctionnalités de l'API

L'API offre les fonctionnalités suivantes :

* **`/`** : Endpoint de base pour vérifier que le service est opérationnel.
* **`/health`** : Vérifie l'état de la connexion à la base de données.
* **`/inscription`** : Enregistrement d'un nouvel utilisateur avec e-mail/mot de passe.
* **`/connexion`** : Authentification d'un utilisateur existant par e-mail/mot de passe.
* **`/connexion-google`** : Authentification et inscription via Google OAuth.
* **`/api/generer-cle`** : Génère une clé API pour l'utilisateur authentifié.
* **`/api/coffre/ajouter`** : Ajoute une transaction au "coffre-fort" de l'utilisateur.
* **`/api/coffre`** : Liste toutes les transactions du "coffre-fort" de l'utilisateur.
* **`/api/me`** : Récupère les informations de profil de l'utilisateur authentifié.

Toutes les routes sous `/api` sont protégées et nécessitent un token d'authentification valide dans l'en-tête `Authorization`.

---

### ⚠️ Avertissement de Sécurité

**Ne stockez jamais d'informations sensibles (mots de passe, clés, etc.) directement dans votre code source**. Utilisez toujours les variables d'environnement, surtout si votre code est hébergé sur un dépôt public.
