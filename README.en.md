# 1c-ai-data-guard

[Русская версия](README.md)

A kit for working with 1C:Enterprise databases together with AI agents without handing them real personal data.
Two profiles: **Kazakhstan** (IIN/BIN, KZ IBAN, BIC, `+7` numbers) and **Russia** (INN, KPP, OGRN, SNILS, settlement accounts).

Main idea: what is safe is not data that is masked, but data the model never had. Hence the layers below.

| Layer | What it does | Status |
|---|---|---|
| 1. Depersonalized copy | A 1C external data processor replaces personal data in a copy of the database with synthetic values that keep valid check digits. The agent works with the copy | works: KZ profile verified on an Accounting for Kazakhstan 3.0 copy, RU profile on an Accounting 3.0 copy |
| 2. Gateway for live data | A proxy between the AI client and 1C OData: allow-list of entities and fields, token substitution, no filters by real values | works (`gateway/`), verified against a stub source and against live 1C OData through IIS |
| 3. Leak check | "Canaries": known fake values planted in the source, an attack battery (26 attacks on live OData) against the gateway, then a search for every canary in responses and logs | works (`canary/`) |
| Core | Validation and generation of identifiers, search and replacement in text | `dataguard/` |

## Quick start

Requirements: Windows, 1C:Enterprise 8.3 (tested on 8.3.27), Python 3.10+ with no extra packages, PowerShell.

### Scenario 1. A depersonalized copy for development and tests

1. **Copy the file database** into a folder whose path contains `_test` (e.g. `D:\Bases\buh_test`); without `_test` the processor replaces nothing. Do not copy the event log.
2. **Build the processor** from `1c/src` (any file database will do, even an empty one):
   ```
   1cv8.exe DESIGNER /F"<any database>" /DisableStartupDialogs /LoadExternalDataProcessorOrReportFromFiles "1c\src\ОбезличиваниеДанных.xml" "1c\build\ОбезличиваниеДанных.epf"
   ```
3. **Inventory** (read only, no real values in the report): `.\1c\run.ps1 -BasePath D:\Bases\buh_test -User Admin -Profile KZ -Mode ИНВЕНТАРИЗАЦИЯ -Report inventory.txt`. `KZ` is Accounting for Kazakhstan, `RU` is Accounting (Russia). Add customized attributes missing from `1c/rules/<profile>.txt` to your copy of the rules.
4. **Depersonalize** (secret: any string of 16+ characters; the snapshot holds hashes, not values):
   ```
   .\1c\run.ps1 -BasePath D:\Bases\buh_test -User Admin -Profile KZ -Mode ВЫПОЛНЕНИЕ -ConfirmTestCopy `
       -Rules 1c\rules\kz.txt -Secret "<secret>" -Snapshot snapshot.txt -Report run.txt -TimeoutSec 7200
   ```
5. **Verify**: modes `ПРОВЕРКА` (`-Rules ... -Snapshot snapshot.txt`) and `ОСТАТКИ`. Then hand the copy to the AI agent and delete the snapshot and the secret.

For another platform version pass `-Platform "C:\Program Files\1cv8\<version>\bin\1cv8.exe"`.
If the platform asks "Allow opening this file?", run the `ЗАЩИТА` mode once (copies only).

### Scenario 2. AI reads a live database through the gateway

1. **Publish OData** of the database (IIS or Apache), enable the needed objects in the standard OData interface, create a read-only 1C user for the gateway.
2. **Write a policy** starting from `gateway/examples/kz.policy.json` or `ru.policy.json`; set `upstream.base_url`. Personal fields are `token:<class>`, the rest `pass`. Whatever is not in the policy the AI never sees.
3. **Run the gateway** under a separate Windows account (`DATAGUARD_SECRET`, `ODATA_USER`, `ODATA_PASSWORD`, optional `DATAGUARD_CLIENT_TOKEN`): `py -m gateway.server --policy my.policy.json --port 8790`.
4. **Check it before connecting AI**: `py -m canary --selftest`, then canaries against your live database (see "Leak check").
5. **Connect the AI client**: point any OData MCP server or script at `http://127.0.0.1:8790` instead of 1C (e.g. `http://127.0.0.1:8790/Catalog_Контрагенты?$top=10`), with the `X-Gate-Token` header if a client key is set.

## Core (`dataguard/`)

Python standard library only.

- `checksums.py` - IIN, BIN, IBAN, INN, SNILS, OGRN: validation and generation. Verified against public examples (the ISO registry IBAN, INN and OGRN of large banks, the SNILS example from the algorithm description). The IIN/BIN algorithm matches the standard Accounting for Kazakhstan check (`БИНИИНСоответствуетТребованиям`): weights 1..11, modulus 11, and when the remainder is 10 a second pass with weights 3..11, 1, 2.
- `scanner.py` - pattern search per profile, deterministic tokens such as `[[iin:M4T2Q9XZ7K]]` (HMAC-SHA256 with a gateway secret), a dictionary of known values for names in free text, `leak_check`.

```
py -m unittest discover -s tests
```

## Gateway to OData (`gateway/`)

A proxy between an AI client (any OData MCP) and 1C OData. The client talks to the gateway, not to 1C; only the gateway knows the 1C address and credentials (environment variables); redirects are disabled.

```
set DATAGUARD_SECRET=<at least 16 characters>
set ODATA_USER=... & set ODATA_PASSWORD=...
py -m gateway.server --policy gateway\examples\kz.policy.json --port 8790
```

- **Read only.** `GET` and `HEAD`; everything else returns 405. Allowed query options: `$select`, `$filter`, `$top`, `$skip`, `$orderby`, `$count`, `$format=json`. `$expand`, `$metadata` and `$batch` are unavailable.
- **Allow-list.** The policy (`*.policy.json`) lists entity sets and fields. Fields outside the policy never leave the gateway and cannot be selected. Field mode is `pass` (returned as is, but strings go through a guard that replaces IIN/BIN, IBAN, phone and e-mail patterns with tokens) or `token:<class>` (the value becomes a token `[[class:XXXXXXXXXX]]`, HMAC with the gateway secret).
- **Filters do not expose values.** A protected field can be searched only by a token taken from a gateway response (the gateway substitutes the real value when it queries 1C), with `eq` and `ne` only. A real IIN, a name, a substring, `or`, functions or sorting by a protected field are rejected. This closes guessing: an unknown token finds nothing.
- **Limits and errors.** `$top` is clipped by the policy; upstream error text is never forwarded (a generic message with a status); the gateway log holds method, entity, status and row count but no values.
- Optional `X-Gate-Token` header (`DATAGUARD_CLIENT_TOKEN`): another process on the machine cannot use the gateway without it.

The token secret and the 1C credentials must not be reachable from the AI session: run the gateway under a separate OS account.

## Leak check (`canary/`)

```
py -m canary --selftest                       :: no 1C: gateway over a stub source
py -m canary --gateway http://127.0.0.1:8790 --canaries canaries.json   :: live gateway
```

`make_canaries()` creates invented but plausible data (IIN/INN with valid check digits, phones, e-mail, accounts, names, passport, free text mixing them). The battery in `canary/battery.py` tries a real IIN and a name in a filter, substrings, `or`, sorting, `$expand`, metadata, batch requests, writes, path escapes, upstream error echo, an IIN inside a `pass` field. After the run every canary is searched for in the responses and the gateway log in any format (with spaces, dashes). The tests in `tests/test_gateway.py` check both the protection and the detector itself: a deliberately weak policy (names or a passport as `pass`) must leak, and does.

**Live check (OData of Accounting for Kazakhstan through IIS).** The processor enabled the standard OData interface for catalogs (`ОДАТА` mode), planted eight canaries with codes `CANDG0001…` straight into the counterparties catalog (`КАНАРЕЙКИ`, later `УДАЛИТЬКАНАРЕЙКИ`), the database was published in IIS and the gateway stood in front of it. Main gateway (comment field outside the policy): all 8 canaries were retrieved through it (names and IIN as tokens), 26 attacks, 0 leaks. A control experiment with a weak policy (comment as `pass`) gave 9 name leaks: the IIN, phone and e-mail in the same comment were replaced by the guard, but a name without a pattern passed through. Important: canaries must appear in the gateway responses (hence a distinct code and retrieval by it), otherwise "0 leaks" proves nothing.

What this proves and what it does not: the gateway does not return canaries from fields outside the policy and does not let them be guessed by filters. It does not prove that allowed fields hold no personal data missing from the pattern list (so names, titles and texts need `token:*` mode, not `pass`), and it does not replace a run on your own database.

## Depersonalization processor (`1c/`)

A 1C external data processor run from the command line on a copy of a file database: `1c/run.ps1`. Modes (Russian names are the actual values):

| Mode | What it does |
|---|---|
| `ИНВЕНТАРИЗАЦИЯ` (inventory) | Read only: which sensitive attributes exist, how many are filled, a masked sample (digits become 9, letters А/а), extensions, scheduled jobs. Real values never reach the report |
| `ВЫПОЛНЕНИЕ` (execute) | Replacement by rules in `1c/rules/<profile>.txt`, scheduled jobs off. Only if the base path contains `_test`, `ПОДТВЕРЖДЕНИЕ=ТЕСТОВАЯ_КОПИЯ` is given and the base is not yet depersonalized |
| `ПРОВЕРКА` (verify) | Against a snapshot of hashes of the original values: none may remain; every synthetic IIN and IBAN has a valid check; all users are depersonalized |
| `ОСТАТКИ` (leftovers) | Searches ALL string attributes and tabular sections (not just the rules) for values that look like IIN/BIN, KZ IBAN, e-mail |
| `СНИМОК` (snapshot) | Read only: writes hashes of the original values per rules (run on a copy before replacement if the snapshot was lost) |
| `ЗАЩИТА` (protection) | Test copies only (`_test` in the path): turns off the unsafe-action warning for the database users |
| `САМОПРОВЕРКА` (self-test) | Samples and a mass check of the generators (1000 values each of IIN, BIN, IBAN, INN 10/12, SNILS) |
| `ОДАТА`, `ОДАТАСБРОС`, `КАНАРЕЙКИ`, `УДАЛИТЬКАНАРЕЙКИ` | For live gateway checks: enable / clear the standard OData interface for catalogs, plant canaries from JSON, delete them |
| `ПОЛЬЗОВАТЕЛИ` (users) | Replaces logins, full names and passwords of database users and the names of "Users" catalog items (except the ones kept); `ПРОВЕРКАПОЛЬЗОВАТЕЛЕЙ` only checks |

Values are replaced deterministically (HMAC-SHA256 with a per-run secret): one original identifier always becomes the same synthetic one, so references and matches between catalogs and documents survive. Writes use `ОбменДанными.Загрузка`, in batches of 500; open transactions are rolled back on error.

Results on database copies (checked against a snapshot of hashes of the original values, independently, in the same processor):

| Profile | Database | Volume | Result |
|---|---|---|---|
| KZ | Accounting for Kazakhstan 3.0 | 20k counterparties, 1k individuals, 17k contracts, documents | 20 rule groups without errors; of 6,049 identifier and account values 0 originals remain; 1,275 KZ IBANs with a valid check; 8 identifiers of 11 digits were already like that in the source (typos) and kept their length |
| RU | Accounting 3.0 | 580 counterparties, documents, payroll statements, reporting (89 rule groups with tabular sections) | 0 originals of 3,055; all 1,811 INNs with a valid check; the leftover search finds no personal data (what remains: budget classification codes, document numbers, service identifiers) |

### Known gaps

- Free text without rules, amounts, dates and document numbers stay. Rules are written by hand from the inventory results.
- Tabular-section rules use `Kind.Object.TabularSection` keys. For rows without their own INN the person name is derived from the document and row number, so it may differ from the same person's name in the catalog.
- Identifiers of non-standard length keep their length instead of getting a check digit.
- Values inside `ХранилищеЗначения` and nested XML are not searched; attachments stored in volumes on disk are not touched; the event log is not cleaned (the copy is made without it); external users are not processed.
- Run once per copy: a completion mark prevents a second run (it would break value correspondence).

### Platform pitfalls (1C 8.3.27) found along the way

- `Формат(0, "ЧГ=0")` returns an **empty string**, not `0`. Take digits from the string `"0123456789"` and pad zeros with `Прав("000..." + Формат(...), N)`. Because of this synthetic numbers lost zeros: an IIN with check digit 0 came out 11 digits long, an IBAN shorter than 20.
- `ПолучитьHMAC` is unavailable; HMAC-SHA256 is built by hand on `ХешированиеДанных`.
- `Новый Запрос(...).Выполнить()` and `Новый Файл(...).Существует()` need an intermediate variable; `Попытка` is a keyword; `СтрПовторить` does not exist.
- An error inside an open transaction without a rollback silently discards **all** later writes when the session ends, while the report still says "changed N": roll back in a `Пока ТранзакцияАктивна()` loop.
- A register recorded by a recorder is written only with a set filtered by `Регистратор`. Changing a dimension of an information register inside a set filtered by it fails: delete the old records and write new ones under the new key.
- The platform may ask "Allow opening this file?" when an external processor starts, if the user has the unsafe-action warning on. The `/DisableUnsafeActionProtection` key is not always enough; the flag is cleared by the `ЗАЩИТА` mode or through the COM connector (`InfoBaseUsers`, `UnsafeOperationProtection.UnsafeOperationWarnings = False`; members must be accessed through `InvokeMember`, PowerShell does not see them directly).
- A validity check that skips values of the wrong length does not see shortened numbers: use the generator self-test.
- `.ps1` files with Cyrillic and no BOM are read as ANSI by Windows PowerShell 5.1: save as UTF-8 with BOM.

## What the kit does not promise

- Tokens protect identifiers and known values. Amounts, dates and document numbers remain, and can be used to recognize a counterparty.
- Free text without a dictionary (abbreviations, other legal forms) may pass in the clear. That is why the gateway works on an allow-list of fields.
- This is not legal advice: the transfer of personal data abroad is regulated by law, ask a lawyer.

More in `docs/ARCHITECTURE.md` (Russian).

## License

MIT
