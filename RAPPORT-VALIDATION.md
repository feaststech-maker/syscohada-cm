# Validation AutoRun Hostinger 1.0.0

Date : 11 novembre 2026. Application embarquée : SYSCOHADA CM Laravel 0.2.0.

La suite finale a exécuté **57 tests, tous réussis**, sans test ignoré lors de cette validation.

| Vérification | Résultat et portée |
| --- | --- |
| 30 tests des fonctions de sécurité | Configuration, DNS, ZIP hostiles, limites d’extraction, fichiers privés, verrouillage, conservation des clés et masquage des secrets : réussite. |
| 20 tests de l’orchestrateur | Précontrôle sans modification, conflits, concurrence, absence de mutation avant installation, SQL privé, accord ACME, échecs et santé HTTPS : réussite avec commandes serveur simulées. |
| 7 tests d’intégration PHP 8.4.27 / PostgreSQL 17.11 | Réelle instance isolée temporaire, migrations Laravel, modèles SQL du kit, rôles distincts, TLS avec vérification du certificat, initialisation et reprise, autorisations, RLS et tableau de bord HTTP 200 : réussite. |
| Lanceur Linux/macOS | Quatre modes, entrées invalides, caractères spéciaux et refus de l’accord ACME : réussite avec OpenSSH simulé. Syntaxe Bash vérifiée. |
| Lanceur Windows | Parseur PowerShell 7.5.4 puis quatre modes avec SSH/SCP simulés sous Linux : réussite. Trois cibles invalides refusées avant transfert et arrêt après échec SSH vérifiés. Exécution native Windows 5.1 non réalisée. |
| Code PHP, JSON et paquet | Syntaxe PHP et JSON valide ; empreinte du ZIP applicatif conforme ; extraction réelle contrôlée. |

Les essais n’ont contacté aucun VPS Hostinger. L’installation effective des paquets, les services systemd/Nginx/PHP-FPM et l’émission d’un certificat Let’s Encrypt doivent encore être validés sur la cible Debian 13. Les tests automatisés de l’orchestrateur simulent ces actions ; ils ne constituent pas une recette complète du serveur.

Le contrôleur n’annonce la disponibilité qu’après les contrôles exécutés sur le VPS : rôle applicatif limité, RLS forcée, isolation hors contexte, interface Laravel et réponses HTTPS 200 avec la page attendue. Une erreur bloque la disponibilité et conserve les données. Une reprise utilise les mêmes clés et identités ; elle ne réinitialise pas la base. Après une coupure pendant l’extraction, un dossier temporaire privé peut rester sur place, mais il ne bloque pas une nouvelle tentative.

L’application et ses limites fiscales restent celles de la version 0.2.0. L’installation n’homologue pas une DSF et ne déverrouille pas l’export d’un canevas DGI non qualifié.

## Reproduire les tests

Depuis le dossier du kit, les tests Python isolés utilisent uniquement la bibliothèque standard :

```bash
python3 -m unittest discover -s tests -v
```

Sans variables supplémentaires, les sept tests d’intégration sont explicitement ignorés. Pour les activer, utiliser un compte Linux non privilégié, PHP 8.4 avec les extensions de l’application, OpenSSL et les binaires PostgreSQL 17 :

```bash
PHP_CLI=/chemin/vers/php8.4 PG_BIN=/chemin/vers/postgresql/17/bin python3 -m unittest discover -s tests -v
```

Ces tests créent leur propre instance PostgreSQL temporaire sur un port local disponible ; ils n’utilisent pas la base de production.
