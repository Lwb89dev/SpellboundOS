# Analisi statica Bip 6, OTA 4.6.0.3

Stato 14 novembre 2026. Le osservazioni riguardano l'OTA identificato dal
SHA-256 `ee06079610eaf9b4ffbe35c7a6ddc604ee2aba00c3a66d85101ed2a6556d6df4`.
Non è una lettura della flash effettiva. Le stringhe dimostrano che il software
contiene riferimenti a componenti, non che ognuno sia montato o in uso sulla
revisione posseduta. Non sono stati recuperati sorgenti o driver funzionanti.

## Metodo ed evidenze

REA 6.9.0, usando Binwalk 3.1.0, ha inventariato lo ZIP e scansionato firmware,
bootloader e recovery. Le evidenze complete sono sotto `firmware/rea-*.json`;
le firme rilevate da Binwalk sono candidati, non formati o partizioni validati.
REA non ammette RISC-V come raw binary nel suo percorso Ghidra. È stata quindi
usata separatamente la versione headless Ghidra 12.1.2, con linguaggio
`RISCV:LE:32:default` e compilatore `gcc`. Binwalk e Ghidra sono stati estratti
in `/tmp/spellbound-tools` dai pacchetti Arch, verificati con le rispettive
firme del keyring pacman. REA è stato eseguito da CLI, senza configurare MCP.

`python3 inventory_firmware.py firmware/bip6-4.6.0.3.zip --output analysis/hardware-strings.json`
rigenera l'inventario delle stringhe con hash di ogni membro e offset nei membri
decompressi. Non contiene indirizzi hardware né ne dimostra il funzionamento.
La ricerca è limitata ai quattro eseguibili selezionati e ai pattern dello script.

## Avvio e verifica: osservazioni e limiti

L'header del bootloader a offset `0x400` inizia con istruzione RISC-V e contiene
`HDRZ` e il valore `0x80c0022c`. È stato importato unicamente il file da `0x400`
in poi, assumendo base `0x80c00000`, con entry `0x80c0022c`. Questa mappatura è
un'ipotesi, rafforzata dal fatto che Ghidra trova stringhe e riferimenti coerenti;
non è una misura del bus. Gli script sono in `analysis_scripts/`, il progetto e
il log integrale in `firmware/ghidra-project/` e `firmware/ghidra-boot.log`.

Con tale mappa il codice a `0x80c00918` richiama il caricatore per
`/mnt/system/firmware_sign.bin` a `0x70160000`, poi salta a quell'indirizzo
solo se il caricatore restituisce successo. Il caricatore a `0x80c00876`
chiama `0x80c0e2b6`; in caso di errore compare la stringa a file offset
`0x3310c`, `firmware secure verify failed!!!`. In pseudocodice, `0x80c0e2b6`
separa gli ultimi 64 byte del file, passa i byte precedenti a funzioni associate
alla stringa `SHA256`, e invia il risultato da 32 byte e i 64 byte finali a una
verifica. `0x80c0e144` passa a sua volta 64 byte incorporati nel bootloader a
un'ulteriore routine. Vedi `firmware/ghidra-verify2.log`. Un controllo
indipendente in `analysis_scripts/check_signature.py` verifica che quei 64 byte
sono una chiave pubblica ECDSA secp256k1 e che la firma `r || s` negli ultimi
64 byte del firmware è valida sullo SHA-256 di tutti i byte precedenti. Anche
`recovery_sign.bin` e `fct_test_sign.bin` verificano con la stessa chiave e lo
stesso schema. Un byte alterato causa il fallimento della verifica offline per
ciascuno dei tre file. Questo conferma lo schema per questi file, non le
condizioni reali di ogni percorso di boot.
L'esistenza di modalità di sviluppo o di altri percorsi di avvio non è dimostrata.
Ghidra segnala istruzioni RISC-V
custom e accessi non mappati, quindi il pseudocodice è incompleto.

Il percorso raw recovery seleziona partizioni `recovery0`, `recovery1` o
`recovery_ota`, controlla un header `RECO` e carica dati da offset `0x1000` a
`0x80d00000`. È visibile un percorso di validazione, ma istruzioni custom non
decodificate impediscono di dimostrarne i dettagli o l'aggirabilità. Non è una
via di avvio alternativa accertata. Vedi `firmware/ghidra-recovery-check3.log`.

Non si può affermare che l'OTA sia un'immagine di ripristino verificata, che un
bootloader sbloccabile esista, né che cambiare filehash produca un firmware
avviabile. Non scrivere bootloader, recovery, flash o impostazioni permanenti
senza una via di recupero sperimentata.

## Inventario delle interfacce candidate

| Sottosistema | Indizi statici | Da accertare |
|---|---|---|
| SoC/RTOS | `board_mhs003`, `MHS003_A1/A2/A3`, percorso FreeRTOS `portable/GCC/mhs003`; istruzioni RISC-V | variante CPU, estensioni, MMIO, interrupt, clock, RAM e mappa memoria |
| Display | `dev_lcd`, `display_panel_read_id`, `hal_display_init`, VGLite | controller, alimentazioni, bus e sequenza di init |
| Touch | `dev_ztw622`, `drv_touch_ztw622_probe`, routine I²C | presenza su questa unità, indirizzo, GPIO, interrupt e protocollo |
| Luce | `dev_stk31e60`, lettura/scrittura registri | presenza, bus, indirizzo e calibrazione |
| Memoria | NAND, FTL, flash, PSRAM, partizioni, backup | modello, organizzazione, ECC, bad block, partizioni e dati unici |
| Alimentazione | PMIC e caricatore `cw6305` | componente effettivo, registri e limiti di sicurezza |
| Radio | `rtl8763`, UART, file `extfw/pamir/rtl8763_pack.bin` | ruolo esatto, trasporto, firmware e comandi di controllo |
| Sensori movimento | sensor hub separato con `dev_lsm6dso`, `dev_bmi2xx`, bus SPI/I²C; configurazioni AKM09918C/MMC5603 | quale variante sia effettivamente presente; bus e registri |
| Audio/GNSS | riferimenti a speaker/audio e firmware GNSS | codec, amplificatore, routing audio, chip e controllo GNSS |

Le funzioni disponibili nei blob possono aiutare a ricostruire interfacce ma
non equivalgono a sorgente riutilizzabile, né a componenti liberamente
redistribuibili. Per il progetto open source serve implementare e verificare
driver separati, usando specifiche disponibili e misure sulla scheda.

## Sequenza di lavoro

1. Mappare i loader e la catena di verifica, individuare una modalità di
   ripristino e ottenere una copia verificabile di flash e dati specifici.
2. Identificare revisione, chip, alimentazioni, pin e bus con evidenza fisica
   e/o diagnostica non distruttiva; mappare inizializzazione e protocolli.
3. Preparare un ambiente RISC-V e un HAL con test fuori dispositivo; procedere
   solo quando il percorso di boot e recupero è riproducibile.
4. Progettare il protocollo companion con autenticazione reciproca, cifratura
   autenticata, protezione replay e gestione delle chiavi; studiare a parte
   notifiche Android, chiamate e limiti delle risposte dei singoli client. Il
   Bluetooth classico per audio/chiamate potrebbe richiedere lavoro distinto
   dalle notifiche BLE: non è ancora accertato per questo hardware.

## Verifica aggiuntiva del 15 novembre 2026

Il controllo riproducibile `analysis_scripts/verify_ota_signatures.py` legge
l'archivio originale e verifica anche `bootloader_sign.bin` e
`sensorhub@mhs003_sign.bin`: entrambi hanno firma ECDSA secp256k1 valida con la
stessa chiave pubblica e lo stesso schema SHA-256 / `r || s` dei tre eseguibili
precedenti. Per tutti e cinque, un byte del payload alterato non verifica. I
risultati e gli hash sono in `analysis/ota-signatures.json`.

La chiave proviene dal bootloader nello stesso archivio: la verifica dimostra
coerenza crittografica interna, non autentica indipendentemente il pacchetto e
non dimostra dove o quando il dispositivo controlli ogni immagine. Il fatto
che il bootloader verifichi con una chiave che esso stesso contiene non dimostra
come venga autenticato durante l'avvio.
