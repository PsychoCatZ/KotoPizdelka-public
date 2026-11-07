import { useState } from "react";
export type BackupMode = "export" | "verify" | "restore";
export function ProfileBackupForm({ mode, busy, submit }: { mode: BackupMode; busy: boolean; submit: (mode: BackupMode, password: string) => void }) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const valid = Array.from(password).length >= 12 && Array.from(password).length <= 128 && new TextEncoder().encode(password).length <= 512;
  return <form className="modal-body" autoComplete="off" onSubmit={event => { event.preventDefault(); if (valid && (mode !== "export" || password === confirm) && (mode !== "restore" || acknowledged)) submit(mode, password); }}>
    <p className="form-intro">{mode === "export" ? "Сохрани ключ аккаунта, контакты и историю в файл с отдельным паролем. Запомни пароль: без него восстановить копию нельзя." : mode === "verify" ? "Выбери сохранённый файл и введи пароль копии. Проверим расшифровку и данные, не меняя текущий профиль." : "Восстановление доступно только на устройстве без профиля. Существующие данные не заменяются. Нужен пароль копии, а не пароль Windows."}</p>
    {mode === "restore" && <><p className="field-hint">История вернётся как архив. Для новых сообщений создай новое знакомство: старые цепочки ключей не возобновляются. В аккаунт нужно войти заново.</p><label className="backup-ack"><input type="checkbox" checked={acknowledged} onChange={event => setAcknowledged(event.target.checked)} disabled={busy} />Прежнее устройство больше не использует этот профиль. Это восстановление после потери, а не подключение второго устройства.</label></>}
    <label>Пароль резервной копии<input type="password" value={password} onChange={event => setPassword(event.target.value)} minLength={12} maxLength={256} autoComplete="off" disabled={busy} required /></label>
    {mode === "export" && <label>Повтори пароль<input type="password" value={confirm} onChange={event => setConfirm(event.target.value)} maxLength={256} autoComplete="off" disabled={busy} required /></label>}
    <p className="field-hint">От 12 до 128 символов. Используй длинную фразу и храни копию отдельно от устройства. Файл и пароль не отправляются на relay.</p>
    <button className="button primary full" disabled={busy || !valid || (mode === "export" && password !== confirm) || (mode === "restore" && !acknowledged)}>{busy ? "Работаем с копией…" : mode === "export" ? "Выбрать место и сохранить" : mode === "verify" ? "Выбрать файл и проверить" : "Выбрать файл и восстановить"}</button>
  </form>;
}
