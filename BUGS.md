# BUGS.md — трек PROTOCOL (conformance SPEC v2.1)

Формат: каждый баг → фикс + регрессионный тест. Проверки (a)–(e) прогнаны в
`milky-core/internal/kal2/conformance_test.go` и `internal/carrier/binding_test.go`.

---

### BUG-2026-09-29-08 — vectors.json: ключевой материал выведен не по формуле §2

- **Severity:** High (test oracle)
- **Platform:** all
- **Status:** FIXED (spec-side)
- **Found by:** `TestVectorHandshakeKeys` / `TestVectorFlights`
- **Issue:** в testdata/vectors.json все HKDF-производные (signature,
  clientRecordKey, serverRecordKey, nonceBase, handshakeVerify, finished,
  resumeSecret, record ciphertext, resume.*, ticket) вычислены с
  `info = mxs-in-v2/transcript/<label>` — без суффикса `/<transcript>`,
  который прямо записан в §2 (`info = mxs-in-v2/transcript/<label>/<transcript>`).
  Реализация соответствует тексту спеки → вектор-файл был непригоден как
  conformance-оракул (любая корректная реализация «не проходила» его).
- **Fix:** `milky-core/cmd/genvec` — генератор векторов по формулам спеки
  (восстановлен удалённый «временный» генератор); vectors.json регенерирован.
  Дескриптор/openTargets/transcript/preauth/migrate совпали байт-в-байт.
- **PR:** spec-side PR в `devin/1790623610-kal2-spec-v2`
- **Regression test:** conformance_test.go — все `keys.*` сверяются с
  спек-формулой в тестовом коде (независимая реализация HKDF).

### BUG-2026-09-29-09 — vectors.json: ticketLen закодирован big-endian

- **Severity:** Medium (test oracle)
- **Status:** FIXED (spec-side)
- **Issue:** `resume.resumeFlight` содержит `ticketLen = 0x004e` (BE 78),
  спека §9.2 требует `[2,LE]` (`0x4e00`). Код PR #7 (`ParseResumeHead`)
  читает LE — вектор непарсабелен спек-имплементацией.
- **Fix:** регенерация vectors.json с LE.
- **Regression test:** `TestVectorResume` — парсинг полёта по LE.

### BUG-2026-09-29-10 — спека §3: порядок payload/padLen/pad в тексте неверен

- **Severity:** Medium (spec text)
- **Status:** FIXED (spec-side)
- **Issue:** текст §3: `ct = AEAD(payload || padLen[2,LE] || pad[padLen])`.
  Имплементация и вектор кладут длину **в конец**: `payload || pad || padLen`.
  Реальное значение несовместимо с текстом.
- **Fix:** правка SPEC.md §3 (spec-side PR).
- **Regression test:** `TestVectorRecord` — impl дешифрует векторную запись.

### BUG-2026-09-29-11 — спека §9.2/9.4: nStreams помечен LE, вектор+код — BE

- **Severity:** Low (spec text)
- **Status:** FIXED (spec-side)
- **Issue:** `nStreams[2,LE]` в тексте против BE в vectors.json
  (`migrate.payload`) и коде PR #7 (checkpoint). Весь wire-формат BE —
  правим текст, не байты.
- **Fix:** SPEC.md §9.2, §9.4 → `[2,BE]`/`[4,BE]`.
- **Regression test:** `TestVectorResume`/`TestVectorMigrate` — BE-парсинг.

### BUG-2026-09-29-12 — неизвестные типы записей <0x80 убивали сессию

- **Severity:** High (forward-compat)
- **Status:** FIXED (code)
- **Issue:** `readRecord` возвращал `ErrFraming` на любой неизвестный тип →
  v2.1-записи (TICKET 0x0A, будущие <0x80) рвали v2-сессию. §12 требует:
  <0x80 — пропускать (AEAD+seq-учёт сохраняется), ≥0x80 — разрыв.
- **Fix:** `session.go` — пропуск неизвестных <0x80 после AEAD-open;
  `protocol.go` — `MsgTicket = 0x0A`.
- **PR:** code PR → `devin/1790199091-kal2-universal-subscriptions`
- **Regression test:** `TestForwardCompatTypes` (0x40/0x0A skip, 0x81 kill).

### BUG-2026-09-29-13 — bound-клиент против unbound-сервера: разрыв вместо фолбэка

- **Severity:** High (interop, проверка (d))
- **Status:** FIXED (code)
- **Issue:** клиент всегда биндил к TLS-exporter; сервер с `binding=∅`
  (спека: «носитель без binding → binding=∅») выдавал signature/handshake
  mismatch → разрыв. Фолбэка на клиенте не было вовсе.
- **Fix:** `ClientConfig.AllowUnboundFallback` (opt-in, дефолт строгий —
  иначе stripping-MitM мог бы молча понизить binding) — один redial
  unbound при падении KAL/2-рукопожатия; `VeilConfig.IgnoreBinding` —
  серверный unbound-режим для смешанных флитов.
- **Regression test:** `TestDialVeilBoundClientUnboundServer`,
  `TestDialVeilUnboundClient` (tolerant / RequireBinding).

### BUG-2026-09-29-14 — §9/§10: resumption/migration и descriptor-публикация не реализованы на impl-ветке

- **Severity:** High (feature gap; проверки (b-resumption), (c), (e-server))
- **Status:** OPEN — зона ответственности PR #7
  (`devin/1790627413-session-migration`, конфликтует с impl-веткой) +
  §10 server-publish нигде не реализован.
- **Issue:** на `devin/1790199091` нет resume.go, TICKET/MIGRATE-обработки,
  descriptor publish/fetch. Проверки «replay при resumption», «миграция в
  момент OPEN/quarantine lane/двойная», «descriptor fetch по rendezvous»
  не выполнимы на этой ветке — зафиксировано честно, не дублирую чужой трек.
- **Частично закрыто здесь:** `descriptor.go` — §10.1 парсер (подпись/pin/TTL)
  + `RendezvousPath` (§10.2 keyed path) + тесты против векторов; билет-
  формат и re-key проверены `TestVectorResume` по спек-формулам.

### BUG-2026-09-29-15 — спека: третий полёт (ClientAuthFlight) не описан; §10.2 epoch-энкодинг не определён

- **Severity:** Low (spec text)
- **Status:** FIXED (spec-side)
- **Issue:** impl шлёт `pskMAC(32) || finished(32)` после server flight —
  в §2 не задокументировано; `epoch` в `kal2-rdvs/` || epoch без типа
  сериализации. Обе дыры делают cross-impl conformance недетерминированным.
- **Fix:** SPEC.md — описание третьего полёта + `epoch` как десятичное ASCII.
