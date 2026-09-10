# 🔐 Test de robustesse SSH (audit d'authentification)

> Script Python (POO) qui teste la résistance d'un compte SSH à une attaque par dictionnaire — **pour des tests d'intrusion autorisés uniquement.**

## ⚠️ Avertissement légal

**À n'utiliser que sur un système que vous possédez, ou pour lequel vous disposez d'une autorisation écrite explicite de test d'intrusion.** Tester des identifiants sur un système sans autorisation constitue un accès non autorisé à un système informatique, illégal dans la plupart des juridictions (en France : art. 323-1 du Code pénal). Le script demande une confirmation explicite avant tout test.

## 🎯 Le projet

Un outil d'audit qui tente une liste de mots de passe contre un compte SSH donné, pour évaluer si le service accepte des mots de passe faibles — le même principe que des outils comme Hydra, mais implémenté ici en Python à but pédagogique. Une temporisation entre les tentatives évite de saturer le service cible.

## 🧱 Architecture (POO)

| Classe | Rôle |
|---|---|
| `SSHAuthTester` | Charge la wordlist, tente chaque mot de passe via `paramiko`, respecte un délai entre tentatives |
| `AuthTestResult` (`@dataclass`) | Stocke et formate le résultat du test |

## 🛡️ Garde-fous intégrés

- Confirmation manuelle obligatoire (taper `AUTORISE`) avant toute tentative
- Délai configurable entre chaque essai (`--delay`, 1 seconde par défaut) pour rester raisonnable envers la cible
- Aucune tentative en parallèle : les essais sont séquentiels, pas un flood

## 🚀 Installation & utilisation

```bash
pip install paramiko
python ssh_auth_tester.py <host> <username> passwords_sample.txt --port 22 --delay 1.5
```

Un fichier `passwords_sample.txt` d'exemple est fourni (mots de passe faibles courants).

## 🛠️ Stack technique

`Python` `POO` `paramiko` `dataclasses` `argparse`

---

*Projet personnel — Bachelor Cybersécurité, dans le cadre strict de tests d'intrusion autorisés.*
