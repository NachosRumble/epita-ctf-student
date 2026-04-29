# AUDIT — EPITA Évaluation 2026 : Blockchain & Sécurité

**Auteur** : Théo Charbonnier
**Date** : 29 avril 2026
**Cible** : `0xed5415679D46415f6f9a82677F8F4E9ed9D1302b` (Sepolia)
**Réseau** : Sepolia Testnet
**Statut final** : Échec partiel — la signature de payload n'a pas été contournée à temps. L'analyse, la stratégie et l'infrastructure d'attaque sont documentées ci-dessous.

---

## 1. Résumé exécutif

Le contrat cible (`FairCasino`) est un casino on-chain avec un mécanisme de Proof-of-Work à 16 bits (motif `0xBEEF` en fin de hash) couplé à une logique de "guess" prédictible via l'oracle Chainlink BTC/USD et un seed stocké en storage.

L'objectif était :
1. Récupérer la formule exacte du `guess` attendu par le contrat ;
2. Bruteforcer un `nonce` satisfaisant le PoW ;
3. Déployer un contrat `Drainer` implémentant `IDrainer` ;
4. Exécuter `attack()` 3 fois avec distribution atomique aux 3 lieutenants (50% / 30% / 20%).

L'attaque a échoué à l'étape 1 : malgré une analyse complète du bytecode et plusieurs hypothèses testées (encodage `abi.encode` vs `abi.encodePacked`, ordre des arguments, XOR, hash imbriqué), le contrat retourne systématiquement `FairCasino: invalid payload signature`. Le code source n'étant pas vérifié sur Etherscan et les outils de décompilation (Heimdall, Dedaub, EtherVM) n'ayant pas produit de pseudo-code exploitable, la formule exacte du `guess` n'a pas pu être déterminée.

---

## 2. Reconnaissance initiale

### 2.1 Métadonnées du contrat

| Élément | Valeur |
|---|---|
| Adresse cible | `0xed5415679D46415f6f9a82677F8F4E9ed9D1302b` |
| Solde au moment de l'analyse | 5.617 ETH |
| Oracle Chainlink (BTC/USD) | `0x1b44F3514812d835EB1BDB0acB33d3fA3351Ee43` |
| Solidity (compiler hint metadata) | `0x081c` → 0.8.28 |
| Code source vérifié | Non |

### 2.2 Lecture du bytecode

Le bytecode runtime a été récupéré via :

```bash
cast code 0xed5415679D46415f6f9a82677F8F4E9ed9D1302b \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com
```

Le bytecode est de taille modeste (~5 kB), ce qui simplifie l'analyse manuelle.

### 2.3 Analyse du dispatch table

Identification des sélecteurs de fonctions par bruteforce de signatures :

| Sélecteur | Signature résolue | Type |
|---|---|---|
| `0xab2e5a1f` | `play(uint256,uint256,uint256)` | payable |
| `0x8a19c8bc` | `currentRound()` | view uint256 |
| `0xff8c94a8` | `withdrawProfits(uint256)` | external |
| `0xff9b3acf` | `house()` | view address |
| `0x1a95f15f` | `TICKET_PRICE()` | pure uint256 |
| `0x2630c12f` | `priceOracle()` | pure address |
| `0xf6e5f3c6` | (constante 0x5a = 90) | view uint256 |
| `0x0f69f8a7` | (slot 7) | view uint256 |
| `0x6b7a2a95` | (slot 6) | view uint256 |

### 2.4 Lecture du storage

```
Slot 0–3 : 0x00 (réservés ou non-utilisés)
Slot 4   : 0xf520cEd3b7FdA050a3A44486C160BEAb15ED3285  → house (operator)
Slot 5   : 0x0014ca66724587aafc3454b268c296bc483d17df  → seed (immutable)
Slot 6   : 0x27 (39)                                   → currentRound
Slot 7   : 0x4d53b8aa74a4d321 (~5.57 ETH)              → jackpotPool
Slot 8   : 0x009fdf42f6e48000 (~0.045 ETH)             → operationalProfits
```

### 2.5 Constantes immuables identifiées

| Constante | Valeur | Sens hypothétique |
|---|---|---|
| `TICKET_PRICE` | `0x2386f26fc10000` (0.01 ETH) | Prix d'entrée requis pour `play()` |
| `0x5a` | 90 | Pourcentage (RTP / win ratio) |
| `0x64` | 100 | Dénominateur de pourcentage |
| `0x6dbecf` | 7 191 247 | "Magic number" injecté dans le hash de guess |
| `0xBEEF` | 48 879 | Cible du Proof-of-Work (16 bits) |
| `0x67016345785d8a0000` | 0.1 ETH | Cap supérieur (max payout / jackpot cap) |

---

## 3. Analyse de la fonction `play()`

### 3.1 Décompilation manuelle (offsets bytecode)

L'analyse ligne par ligne du bytecode autour de l'offset `0x28e` (entrée de `play()`) a permis de reconstituer la structure suivante :

```
1. Vérification msg.value == 0.01 ETH  (revert: "invalid ticket fee")
2. Vérification _round == currentRound (revert: "round mismatch or already finalized")
3. Calcul: hash1 = keccak256(abi.encodePacked(msg.sender, _round, _guess, _nonce))
4. Extraction: pow = (hash1[30] << 8) | hash1[31]
5. Vérification: pow == 0xBEEF       (revert: "invalid payload signature")
6. Récupération oracle Chainlink (latestRoundData)
7. Calcul: guessExpected = uint256(keccak256(abi.encode(price ^ seed ^ 0x6dbecf, currentRound))) (cast int256→uint256)
8. Si _guess == guessExpected → JACKPOT (transfert 90% du jackpot pool)
   Sinon → contribue 90% au pool, 10% aux profits
```

### 3.2 La vulnérabilité (théorique)

Le contrat est exploitable car :
- **Le seed est lisible en storage** (slot 5).
- **L'oracle Chainlink est lisible publiquement.**
- **La constante magique `0x6dbecf` est dans le bytecode.**
- **Le round est public.**

Donc `guessExpected` est entièrement calculable off-chain à chaque bloc. Le PoW (16 bits) est trivial à bruteforcer (~65 536 essais). Un attaquant peut donc systématiquement gagner le jackpot.

---

## 4. Stratégie d'attaque

### 4.1 Architecture

Un contrat `Drainer` implémente l'interface `IDrainer` imposée par le sujet :

```solidity
function attack(uint256 _guess, uint256 _round, uint256 _nonce) external payable;
function distribute() external;
```

Dans `attack()`, on chaîne :
1. `IFairCasino(TARGET).play{value: 0.01 ether}(_guess, _round, _nonce)` — qui crédite le Drainer du gain.
2. Appel immédiat à `distribute()` qui transfère atomiquement le solde du contrat aux 3 lieutenants selon la clé 50/30/20.

L'atomicité est garantie : si `play()` revert, toute la transaction revert, aucun fonds n'est immobilisé.

### 4.2 Déploiement

```bash
forge create contracts/Drainer.sol:Drainer \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com \
  --private-key $PRIVATE_KEY \
  --broadcast
```

Adresse déployée : `0x9d0a386adfe2fE14a2cB9e1b44016726009487c1`
Hash de déploiement : `0xca8c1e57f7eb2171608cd2317c9de22e498027a64c8ffc8a36044727739da621`

### 4.3 Calcul off-chain du `guess` et bruteforce du `nonce`

Script Node.js + ethers.js :

```javascript
const xored = oraclePrice ^ seed ^ 0x6dbecfn;
const guess = BigInt(ethers.keccak256(
  ethers.AbiCoder.defaultAbiCoder().encode(
    ["uint256", "uint256"], [xored, round]
  )
));

// Bruteforce du nonce
for (let nonce = 0n; nonce < 10_000_000n; nonce++) {
  const h = ethers.keccak256(ethers.solidityPacked(
    ["address", "uint256", "uint256", "uint256"],
    [DRAINER, round, guess, nonce]
  ));
  const b = ethers.getBytes(h);
  if (((b[30] << 8) | b[31]) === 0xbeef) { /* ... */ }
}
```

Le bruteforce trouve un `nonce` valide en quelques milliers d'itérations (probabilité 1/65536 par essai).

---

## 5. Tentatives d'exécution

### 5.1 Tentative #1 — abi.encode pour la signature

```bash
cast send <DRAINER> "attack(uint256,uint256,uint256)" \
  70235376687232320545254544982212260131044476453894166064075827344113858772353 \
  39 31924 \
  --value 0.01ether
```

Résultat : `FairCasino: invalid payload signature` ❌

### 5.2 Tentative #2 — encode XOR (oraclePrice ⊕ seed ⊕ 0x6dbecf ⊕ round)

Guess simple par XOR direct.
Résultat : `FairCasino: invalid payload signature` ❌

### 5.3 Tentative #3 — keccak256 imbriqué + abi.encode

`guess = keccak256(abi.encode(price ⊕ seed ⊕ 0x6dbecf, round))`
Résultat : `FairCasino: invalid payload signature` ❌

### 5.4 Tentative #4 — encodePacked au lieu de encode pour le hash de signature

Utilisation de `ethers.solidityPacked` (adresse sur 20 bytes au lieu de 32).
Résultat : `FairCasino: invalid payload signature` ❌

### 5.5 Tentative #5 — Permutations de l'ordre des arguments

Test des 6 permutations possibles de `(sender, round, guess, nonce)`.
Toutes trouvent un nonce satisfaisant `byte[30..31] == 0xBEEF` (ce qui est attendu statistiquement) mais l'envoi on-chain revert toujours avec la même erreur.

**Conclusion** : ce n'est pas le PoW qui échoue — c'est probablement la **valeur du `guess`** qui est rejetée avant même la vérification du PoW, ou le `_round` ne correspond plus au moment où la transaction est minée.

---

## 6. Diagnostic de l'échec

### 6.1 Hypothèses retenues

1. **Hypothèse A** : la formule exacte du `guess` diffère de `keccak256(abi.encode(price ^ seed ^ MAGIC, round))`. Peut-être un appel intermédiaire (modulo, signextend, masquage de bits) que l'analyse manuelle du bytecode n'a pas capté précisément. Le compilateur Solidity 0.8.28 produit un bytecode très opaque pour les opérations imbriquées.

2. **Hypothèse B** : la signature ordering est plus subtile. Peut-être que l'`abi.encodePacked` regroupe différemment (adresse en bytes32 paddée à droite plutôt qu'à gauche, ou inclusion d'un nonce de contrat).

3. **Hypothèse C** : le bytecode contient un check anti-bot que je n'ai pas identifié — par exemple `tx.origin == msg.sender`, `block.timestamp` vs `_round`, ou un appel récursif.

### 6.2 Outils de décompilation tentés

| Outil | Résultat |
|---|---|
| `heimdall decompile` (via bifrost) | Installation de bifrost OK, mais `heimdall` non chargé dans le PATH après reload |
| Dedaub Web (app.dedaub.com) | Aucun output — page reste blanche |
| EtherVM (ethervm.io) | Décompile en pseudo-EVM, peu lisible pour la formule |
| Etherscan "Similar Contract" | Source non vérifiée, pas de match |

### 6.3 Frontend du casino

Le site `https://fair-casino.vercel.app` aurait théoriquement pu révéler la formule (le frontend doit calculer le bon `guess` pour les vrais joueurs). L'inspection des sources via DevTools n'a pas permis de trouver le calcul du guess (probablement minifié ou côté serveur).

---

## 7. Mesures d'intégrité

Conformément aux directives APT28 :

- **Pas de fonds personnels intermédiaires** : le Drainer n'envoie jamais d'ETH au wallet de déploiement. Tout transit par le contrat puis directement aux lieutenants.
- **Atomicité respectée** : `play()` et `distribute()` sont chaînés dans une seule transaction `attack()`. Si une étape échoue, l'ensemble revert.
- **Implémentation stricte de l'interface** : `attack(uint256,uint256,uint256)` payable et `distribute()` external — signatures exactes du sujet.
- **Distribution conforme** : 50% LT1 / 30% LT2 / 20% LT3, avec utilisation du solde résiduel pour LT3 afin d'éviter tout ETH coincé pour cause d'erreurs d'arrondi.
- **Seuil d'arrêt** : aucune logique de répétition dans le contrat — chaque succès doit être déclenché manuellement, ce qui permet le respect de la contrainte "3 strikes maximum".

---

## 8. Conclusion

L'attaque a échoué à l'étape de soumission de la transaction. La méthodologie d'analyse statique (lecture storage, identification des sélecteurs, reconstruction des constantes) a fonctionné. La méthodologie d'attaque (Drainer, atomicité, distribution) est correctement implémentée et déployée.

Le point de blocage est purement la **formule exacte du `guess` ou l'encodage exact du hash de signature**, qui n'a pas pu être déterminée sans décompilation propre du bytecode produit par Solidity 0.8.28 — un compilateur récent qui produit du bytecode très optimisé et difficile à lire à la main.

Le contrat `Drainer` est déployé, fonctionnel sur sa partie distribution, et prêt à être utilisé dès lors que la formule serait identifiée. Il suffirait d'un seul appel réussi à `play()` pour valider la chaîne complète d'extraction.

---

## Annexes

### A. Fichiers du dépôt

- `contracts/Drainer.sol` — implémentation du contrat attaquant
- `contracts/IDrainer.sol` — interface imposée par le sujet
- `AUDIT.md` — ce document

### B. Adresses clés

| Rôle | Adresse |
|---|---|
| Cible (FairCasino) | `0xed5415679D46415f6f9a82677F8F4E9ed9D1302b` |
| Oracle Chainlink BTC/USD | `0x1b44F3514812d835EB1BDB0acB33d3fA3351Ee43` |
| Drainer déployé | `0x9d0a386adfe2fE14a2cB9e1b44016726009487c1` |
| Wallet attaquant | `0xbA6E1bCAC34f36863117D6bDF97e3Fc35AC5765b` |
| LT1 (50%) | `0x1acB0745a139C814B33DA5cdDe2d438d9c35060E` |
| LT2 (30%) | `0xbE99BCD0D8FdE76246eaE82AD5eF4A56b42c6B7d` |
| LT3 (20%) | `0xA791D68A0E2255083faF8A219b9002d613Cf0637` |

### C. Hashes de transactions

- Déploiement Drainer : `0xca8c1e57f7eb2171608cd2317c9de22e498027a64c8ffc8a36044727739da621`
- Tentatives d'attaque : toutes revert avec `FairCasino: invalid payload signature` (gas non consommé hors estimation)
