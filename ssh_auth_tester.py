"""
Test de robustesse SSH (audit d'authentification)

⚠️ À N'UTILISER QUE SUR UN SYSTÈME QUE VOUS POSSÉDEZ OU POUR LEQUEL VOUS
AVEZ UNE AUTORISATION ÉCRITE EXPLICITE DE TEST D'INTRUSION.

Ce script teste une liste de mots de passe contre un compte SSH pour
évaluer la résistance du service à une attaque par dictionnaire, dans le
cadre d'un audit de sécurité autorisé. Il inclut une temporisation entre
les tentatives pour éviter de saturer le service cible.

Nécessite la bibliothèque paramiko : pip install paramiko
"""

import argparse
import sys
import time
from dataclasses import dataclass
from typing import Optional

try:
    import paramiko
except ImportError:
    paramiko = None


@dataclass
class AuthTestResult:
    host: str
    username: str
    attempts: int = 0
    success_password: Optional[str] = None

    def __str__(self):
        if self.success_password:
            return (
                f"⚠️ Mot de passe faible trouvé pour {self.username}@{self.host} "
                f"après {self.attempts} tentative(s) : '{self.success_password}'"
            )
        return f"Aucun mot de passe de la liste n'a fonctionné pour {self.username}@{self.host} ({self.attempts} tentative(s))."


class SSHAuthTester:
    """Teste la robustesse d'un compte SSH face à une liste de mots de passe (dictionnaire)."""

    def __init__(self, host, username, wordlist_path, port=22, delay=1.0, timeout=5.0):
        self.host = host
        self.username = username
        self.wordlist_path = wordlist_path
        self.port = port
        self.delay = delay
        self.timeout = timeout

    def _load_wordlist(self):
        with open(self.wordlist_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]

    def _try_password(self, password):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                self.host,
                port=self.port,
                username=self.username,
                password=password,
                timeout=self.timeout,
                banner_timeout=self.timeout,
            )
            return True
        except paramiko.AuthenticationException:
            return False
        except (paramiko.SSHException, OSError) as e:
            print(f"  Erreur de connexion : {e}", file=sys.stderr)
            return False
        finally:
            client.close()

    def run(self):
        result = AuthTestResult(host=self.host, username=self.username)
        passwords = self._load_wordlist()

        for password in passwords:
            result.attempts += 1
            print(f"  Tentative {result.attempts}/{len(passwords)}...")
            if self._try_password(password):
                result.success_password = password
                break
            time.sleep(self.delay)  # limite le débit pour rester raisonnable envers la cible

        return result


def confirm_authorization(host):
    print("=" * 70)
    print("⚠️ AVERTISSEMENT LÉGAL")
    print("=" * 70)
    print(f"Vous êtes sur le point de tester des identifiants SSH contre : {host}")
    print("Cela n'est légal que si vous possédez ce système ou disposez d'une")
    print("autorisation écrite explicite pour ce test d'intrusion.")
    print()
    reponse = input("Confirmez-vous être autorisé à tester cette cible ? (tapez AUTORISE) : ")
    return reponse.strip() == "AUTORISE"


def main():
    parser = argparse.ArgumentParser(
        description="Test de robustesse d'authentification SSH (audit autorisé uniquement)."
    )
    parser.add_argument("host", help="Adresse IP ou nom d'hôte cible")
    parser.add_argument("username", help="Nom d'utilisateur SSH à tester")
    parser.add_argument("wordlist", help="Fichier .txt contenant un mot de passe par ligne")
    parser.add_argument("--port", type=int, default=22, help="Port SSH (défaut : 22)")
    parser.add_argument("--delay", type=float, default=1.0, help="Délai entre tentatives (secondes)")
    args = parser.parse_args()

    if paramiko is None:
        print("La bibliothèque 'paramiko' est requise : pip install paramiko", file=sys.stderr)
        sys.exit(1)

    if not confirm_authorization(args.host):
        print("Autorisation non confirmée. Arrêt du script.")
        sys.exit(1)

    tester = SSHAuthTester(args.host, args.username, args.wordlist, port=args.port, delay=args.delay)
    print(f"\nTest de {args.username}@{args.host}:{args.port}...")
    result = tester.run()
    print("\n" + str(result))


if __name__ == "__main__":
    main()
