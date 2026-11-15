# SpellboundOS

SpellboundOS is a new standalone operating system for the Amazfit Bip 6, developed alongside the SpellboundFit Android companion. See [GOAL.md](GOAL.md) for the project goal and [PROGRESS.md](PROGRESS.md) for the work log.

# Bip 6: acquisizione OTA e analisi iniziale

Per l'analisi con REA/Ghidra, la catena di avvio e l'inventario hardware
consultare [analysis/ANALISI.md](analysis/ANALISI.md).

Il prototipo RV32 sotto `kernel/` gira su **QEMU virt** e comunica sulla sua
UART emulata; non è ancora un firmware Bip 6 e non va installato sull'orologio.
Con Clang, LLD, llvm-objcopy e QEMU installati: `make test` compila, avvia e
verifica banner ed eco seriale. Non include ancora Bluetooth o crittografia.

Rilevazione del 14 novembre 2026 tramite Gadgetbridge sul dispositivo collegato:
Amazfit Bip 6, firmware 4.6.0.3, hardware 0.135.23.0, deviceSource
10158337, product ID 155 e product version 257. Nessuna scrittura sull'orologio.

## Catalogo OTA

`python3 ota_check.py` consulta l'endpoint pubblico Amazfit per questa variante,
con Zepp 10.9.0-play (151983), dalle versioni 4.6.0.3 e 0, nelle regioni
IT, US, PL, CN e RU. Richiede accesso Internet. I parametri seguono il client
[Zelp](https://github.com/otaj/zelp/blob/master/lib/services/firmware_client.dart);
il catalogo [ZeppOS-DevicesList](https://github.com/melianmiko/ZeppOS-DevicesList/blob/main/zepp_devices.json)
associa deviceSource 10158337 a productionId 240. Il server ha risposto con
productionSource 257. I due campi non vanno assunti intercambiabili senza altre
verifiche. La risposta, per tutte le regioni, non propone un aggiornamento da
4.6.0.3; da 0 propone 4.6.0.3 con `diffUpgradeFlag: false`. Questo non prova che
il pacchetto sia un dump completo della flash o una procedura di recupero.

Pacchetto ufficiale: [download Amazfit](https://huami-firmware-cdn.huami.com/10158337/fw_4.6.0.3_202609241131_c67028810ecb4084b4adc9f110f6c52d_watch%40mhs003_ota_sign.zip).
Copia locale: `firmware/bip6-4.6.0.3.zip` (esclusa da Git). Dimensione 118618487
byte; MD5 `6bd12c8430b97faaba434127fbee7d37` coincide con la risposta API;
SHA-256 `ee06079610eaf9b4ffbe35c7a6ddc604ee2aba00c3a66d85101ed2a6556d6df4`.
Il controllo CRC delle 12885 voci ZIP riesce.

## Osservazioni statiche

- `packageDiscription.json` indica piattaforma `mhs003`, firmware 4.6.0.3,
  bootloader 2.0.6 e un comando di aggiornamento del bootloader. `META/fw_info`
  indica anche recovery 2.3.1.
- `update-script` contiene `mkfs("SYSTEM")` e l'estrazione di `META/` e
  `filehash` sul filesystem di sistema. Non eseguirlo sul dispositivo.
- Ci sono `firmware_sign.bin`, `bootloader_sign.bin`, `recovery_sign.bin`,
  sensor hub, risorse, app e modelli di attività. I nomi suggeriscono firme;
  algoritmo, controllo effettivo e possibilità di avvio di codice modificato
  non sono ancora accertati.
- `filehash` elenca 12882 SHA-256: 12881 corrispondono; **META/res_info non
  corrisponde** (atteso `76b3f5426ff0b6a4843e430c4612de7f945504364fefbcd0d9101cf2d12f9107`,
  effettivo `56a3ea9f6d1242714e66665d97316ce1b01bdb9c0c9c85711870f9ca0a0898ee`).
  L'atteso coincide con l'hash di `META/build_info`. La causa e l'effetto sul
  processo OTA sono sconosciuti; la coincidenza col checksum API non verifica
  autenticità crittografica né validità interna del manifesto.

## Prossimi passi

Studiare offline intestazioni, firme e codice di recovery/boot, formato delle app
e relazioni fra manifesto e risorse; cercare documentazione di debug e recupero
per mhs003. Identificare quali componenti gestiscono sensori, raccolta e invio
prima di progettare modifiche. Nessuna immagine privacy modificata o recupero
verificato è ancora disponibile: rimuovere risorse non dimostra che il tracking
sia disattivato, e alterare l'OTA può renderlo non avviabile.
