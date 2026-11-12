# SYSCOHADA CM — AutoRun Hostinger 1.0.0

Ce kit installe l’application **SYSCOHADA CM Laravel 0.2.0** et son module optionnel de comptabilité virtuelle sur un **VPS Hostinger Debian 13 neuf ou dédié**, avec accès administrateur SSH. Le paquet applicatif et ses dépendances de production sont inclus ; l’installateur vérifie son empreinte avant extraction.

Il ne nécessite pas de jeton API Hostinger. Les mots de passe SSH sont saisis directement dans OpenSSH, jamais dans ChatGPT ou dans un fichier de configuration du kit.

## Ce qui est automatisé

- Contrôle du système, du domaine, du paquet et des collisions avec une installation existante.
- Installation des paquets Debian nécessaires à PHP 8.4, PostgreSQL 17, Nginx et HTTPS.
- Préparation d’une base PostgreSQL et de comptes distincts pour la maintenance et le serveur web.
- Configuration de l’isolation RLS, des migrations, du processus PHP-FPM et des fichiers temporaires privés.
- Génération des secrets propres à l’installation, conservation des clés et création de l’administrateur.
- Configuration du site et du certificat HTTPS après accord explicite pour Let’s Encrypt.
- Contrôles de démarrage et affichage du résultat, sans imprimer les secrets.

Le logiciel ne réinstalle pas le système, n’achète pas de VPS, ne modifie pas automatiquement votre DNS ou les règles SSH, et ne remplace pas silencieusement un autre site. Il s’agit d’un installateur de cette version, pas d’un moteur de mise à jour universel.

## 1. Préparer le serveur et le domaine

1. Dans Hostinger, disposer d’un **VPS Debian 13**. Ne réinstallez pas un VPS qui contient déjà vos sites ou données pour essayer ce kit.
2. Relever son **adresse IPv4 publique**, le nom d’utilisateur SSH et le port SSH.
3. Faire pointer un sous-domaine, par exemple `dsf.votredomaine.com`, vers cette IP avec un enregistrement **A** dans la zone DNS autoritaire.
4. Si ce même nom possède des enregistrements A supplémentaires ou un AAAA, vérifier qu’ils correspondent aussi à ce serveur. Un enregistrement IPv6 erroné peut empêcher l’obtention du certificat.
5. Autoriser les connexions entrantes HTTP/HTTPS nécessaires sur **80 et 443** dans le pare-feu Hostinger. Conserver votre accès SSH existant.

Les offres Web/Premium/Business/Cloud ne fournissent pas le VPS/PostgreSQL requis par ce kit. Un VPS sous CloudPanel, CyberPanel ou avec d’autres applications doit être étudié séparément : ne forcez pas les protections du précontrôle pour l’installer dessus.

## 2. Lancer depuis Windows

Extraire complètement le ZIP sur votre ordinateur. Ouvrir **PowerShell dans le dossier extrait**, puis exécuter :

```powershell
powershell -NoProfile -File .\LANCER-WINDOWS.ps1
```

Le lanceur demande l’IP du VPS, le domaine, l’email administrateur/contact du certificat et le nom de l’entreprise. L’utilisateur SSH vaut `root` et le port vaut `22` par défaut.

Si vous utilisez un autre compte ou un autre port :

```powershell
powershell -NoProfile -File .\LANCER-WINDOWS.ps1 -SshUser deploy -SshPort 2222
```

Pour une clé SSH déjà configurée :

```powershell
powershell -NoProfile -File .\LANCER-WINDOWS.ps1 -IdentityFile "$env:USERPROFILE\.ssh\id_ed25519"
```

Pour commencer par le précontrôle :

```powershell
powershell -NoProfile -File .\LANCER-WINDOWS.ps1 -Mode plan
```

Windows doit disposer du client **OpenSSH** (`ssh.exe`, `scp.exe`) et de `tar.exe`. Le lanceur vérifie leur présence. Il conserve la vérification des clés de serveur SSH et respecte la politique d’exécution PowerShell. S’il est bloqué par cette politique, utilisez la méthode console ci-dessous ou la procédure approuvée par votre administrateur ; le kit n’applique pas `ExecutionPolicy Bypass`.

Lors de la première connexion SSH, vérifiez l’empreinte du serveur avant de l’accepter. Depuis la console Web Hostinger, la commande suivante affiche une empreinte publique à comparer :

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

OpenSSH peut demander plusieurs authentifications pour la préparation, le transfert et le lancement. Le lanceur ne mémorise pas le mot de passe SSH. Avec un compte non root, la commande distante utilise `sudo` et peut demander son mot de passe dans le terminal SSH.

## 3. Lancer depuis Linux ou macOS

Depuis le dossier extrait :

```bash
bash LANCER-LINUX-MAC.sh
```

Exemple avec un compte et une clé existants :

```bash
bash LANCER-LINUX-MAC.sh --user deploy --port 2222 --key "$HOME/.ssh/id_ed25519"
```

Précontrôle :

```bash
bash LANCER-LINUX-MAC.sh --mode plan
```

Le client local requiert Bash, Python 3, OpenSSH et tar. Il ne collecte aucun mot de passe SSH.

## 4. Alternative : lancer directement sur le VPS

Transférer et extraire le kit dans un dossier privé de votre compte SSH. À partir de ce dossier :

```bash
cp config.example.json config.local.json
nano config.local.json
sudo bash install.sh --plan --config config.local.json
# Lire les conditions Let’s Encrypt (section 5), puis mettre
# accept_acme_terms à true dans config.local.json après acceptation.
sudo bash install.sh --install --config config.local.json
```

Remplacer toutes les valeurs de l’exemple, notamment `203.0.113.10`, qui est une adresse de documentation et non votre IP. Un précontrôle utilisant cette adresse d’exemple échouera normalement : il doit vérifier votre véritable IP et votre DNS. `config.local.json` contient seulement des paramètres de déploiement, pas les mots de passe.

Pour la première installation, `install.sh` peut installer Python 3 depuis les dépôts Debian signés si nécessaire. Les modes `--plan` et `--status` ne le font pas : ils signalent ce prérequis sans installer de logiciel. Le précontrôle n’installe pas les services applicatifs et ne modifie pas leurs configurations. Un lancement distant de `--plan` transfère toutefois le kit dans un dossier privé unique du VPS.

## 5. Accord pour le certificat HTTPS

L’émission d’un certificat public transmet le domaine et l’email de contact à **Let’s Encrypt**. Les conditions et l’accord d’abonné sont disponibles sur :

https://letsencrypt.org/repository/

Le lanceur demande un accord explicite avant ce déploiement. En exécution directe sans fichier de configuration, `sudo bash install.sh --install` collecte les paramètres et cet accord dans le terminal. Avec un fichier JSON, `accept_acme_terms` vaut `false` par défaut : le déploiement refuse alors d’émettre le certificat. Après lecture et acceptation des conditions, l’exploitant doit mettre cette valeur à `true` avant la commande d’installation avec ce fichier. Cela ne dispense pas d’une configuration DNS correcte et d’un accès HTTP entrant.

Le kit ne contourne aucune erreur TLS et n’utilise pas `curl -k` pour déclarer l’application opérationnelle.

## 6. À la fin

Le résultat donne l’adresse de connexion de l’application et le chemin du fichier privé contenant les premiers identifiants :

```text
/root/syscohada-identifiants.txt
```

Lire ce fichier uniquement dans votre session administrateur sur le VPS et le conserver de manière sécurisée. Le mot de passe initial est généré pour votre installation ; aucun mot de passe partagé n’est inclus dans le kit et les journaux n’en affichent pas la valeur.

Les clés de chiffrement et les données PostgreSQL doivent être sauvegardées avec leurs protections. Ne régénérez pas `APP_KEY` pour réparer une connexion : les pièces justificatives existantes peuvent en dépendre.

## 7. Reprendre ou diagnostiquer

En cas d’interruption, garder le dossier du kit sur le VPS et relancer :

```bash
sudo bash install.sh --resume
sudo bash install.sh --status
```

Les lanceurs locaux acceptent aussi `-Mode resume` / `-Mode status` sous Windows et `--mode resume` / `--mode status` sous Linux/macOS. Ces modes utilisent l’état déjà enregistré sur le serveur. Une reprise exige la même cible et le même paquet ; elle ne doit pas recréer les secrets ou réinitialiser une base existante.

Un échec de démarrage n’entraîne pas une restauration destructrice de PostgreSQL. Le site reste indisponible ou en maintenance jusqu’à correction et reprise. Ne supprimez pas les données pour contourner un diagnostic de collision.

## Vérifications et limites

La suite finale compte **57 tests réussis**, dont sept tests avec PHP 8.4 et une véritable instance PostgreSQL 17 temporaire. Les quatre modes du lanceur Linux/macOS ont été exercés avec OpenSSH simulé, y compris les entrées invalides, les caractères spéciaux dans le nom d’entreprise et le refus de l’accord HTTPS. Le parseur PowerShell 7.5.4 et les quatre modes Windows ont aussi été exercés sur Linux avec SSH/SCP simulés ; une exécution native sous Windows 5.1 reste à vérifier.

Les tests d’intégration PHP couvrent : initialisation et reprise, hachage du mot de passe, refus d’un fichier secret aux permissions publiques, identité stable, connexion applicative soumise à RLS et tableau de bord HTTP 200, refus d’un rôle propriétaire, cache de migration ignoré et autorité de certification invalide refusée. Le logiciel Laravel embarqué possède en plus ses propres tests. Le détail figure dans `RAPPORT-VALIDATION.md`. Ces contrôles ne sont pas un essai complet du provisionnement sur un VPS.

Le kit n’a pas été exécuté sur votre VPS Hostinger : son IP, son domaine et votre session SSH n’ont pas été fournis ici. Le lancement local utilise votre authentification normale pour réaliser ce déploiement. Une réussite sur des tests et sur un environnement de développement ne remplace pas la recette sur le serveur cible.

L’installation ne complète pas les fonctions fiscales absentes du logiciel. La génération exhaustive de la DSF et la qualification du canevas officiel pour la campagne restent distinctes de la mise en ligne. L’export officiel conserve ses blocages.

## Références

- [Hostinger — connexion SSH et console Web](https://www.hostinger.com/support/5723772-how-to-connect-to-your-vps-via-ssh-at-hostinger/).
- [Hostinger — systèmes VPS, dont Debian 13](https://www.hostinger.com/support/1583571-what-are-the-available-operating-systems-for-vps-at-hostinger/).
- [PostgreSQL 17 — connexions TLS](https://www.postgresql.org/docs/17/ssl-tcp.html).
- [PostgreSQL 17 — authentification locale peer](https://www.postgresql.org/docs/17/auth-peer.html).
- [Let’s Encrypt — conditions et accords](https://letsencrypt.org/repository/).
