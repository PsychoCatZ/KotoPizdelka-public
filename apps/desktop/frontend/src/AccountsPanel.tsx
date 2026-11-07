import { useState } from "react";
import type { FormEvent } from "react";
import type { AccountView } from "./api";
export function AccountsPanel({view,busy,authenticate,find,add,decide,logout,refresh,invite}: {
  view:AccountView; busy:boolean;
  authenticate:(login:string,password:string,register:boolean)=>void;
  find:(login:string)=>Promise<string>; add:(login:string)=>void;
  decide:(id:string,accept:boolean)=>void; logout:()=>void; refresh:()=>void; invite:()=>void;
}) {
  const [login,setLogin]=useState(view.login ?? "");
  const [password,setPassword]=useState("");
  const [register,setRegister]=useState(!view.registered);
  const [search,setSearch]=useState("");
  const [found,setFound]=useState<string|null>(null);
  const [finding,setFinding]=useState(false);
  const [findError,setFindError]=useState<string|null>(null);
  function submit(event:FormEvent){event.preventDefault();authenticate(login.trim(),password,register);setPassword("");}
  async function lookup(event:FormEvent){event.preventDefault();setFinding(true);setFound(null);setFindError(null);try{setFound(await find(search.trim()));}catch(reason){setFindError(typeof reason==="string"?reason:"Не удалось найти кота. Повтори позже.");}finally{setFinding(false);}}
  return <div className="modal-body account-panel">
    {!view.authenticated ? <form onSubmit={submit}>
      <p className="form-intro">Выбери логин для своей стаи. Телефон и почта не нужны.</p>
      <div className="account-tabs"><button className={`button ${register?"primary":"secondary"}`} type="button" disabled={busy || view.registered} onClick={()=>setRegister(true)}>Регистрация</button><button className={`button ${!register?"primary":"secondary"}`} type="button" disabled={busy} onClick={()=>setRegister(false)}>Вход</button></div>
      <label>Логин<input value={login} onChange={e=>setLogin(e.target.value)} pattern="[a-zA-Z][a-zA-Z0-9_]{2,31}" minLength={3} maxLength={32} disabled={busy || view.registered} required autoComplete="username" autoCapitalize="none" spellCheck={false} placeholder="Например, kot_vasiliy" /></label>
      <p className="field-hint">3–32 символа: латинские буквы, цифры и _. Начни с буквы.</p>
      <label>Пароль<input type="password" value={password} onChange={e=>setPassword(e.target.value)} minLength={10} maxLength={128} disabled={busy} required autoComplete={register?"new-password":"current-password"} placeholder="Не меньше 10 символов" /></label>
      <button className="button primary full" disabled={busy}>{busy?"Кот проверяет…":register?"Присоединиться к стае":"Войти"}</button>
      <p className="field-hint">Аккаунт привязан к этому профилю. Вход на другом устройстве пока не переносит ключи и историю.</p>
    </form> : <>
      <p className="form-intro">Твой логин: <strong>@{view.login}</strong></p>
      <form onSubmit={lookup}><label>Найти кота по логину<input value={search} onChange={e=>{setSearch(e.target.value);setFound(null);}} minLength={3} maxLength={32} pattern="[a-zA-Z][a-zA-Z0-9_]{2,31}" required disabled={busy||finding} autoCapitalize="none" spellCheck={false} placeholder="Точный логин собеседника" /></label><button className="button secondary full" disabled={busy||finding}>{finding?"Ищем…":"Найти кота"}</button></form>
      {findError && <p role="alert">{findError}</p>}
      {found && <div className="account-request"><span>@{found}</span><button className="button primary" disabled={busy||found===view.login} onClick={()=>add(found)}>Позвать в беседу</button></div>}
      <div className="account-request"><h3>Знакомства</h3><button className="button secondary" disabled={busy} onClick={refresh}>Обновить</button></div>
      {view.requests.length===0 && <p className="field-hint">Здесь появятся запросы новых собеседников.</p>}
      {view.requests.map(r=><div className="account-request" key={r.id}><div><strong>@{r.login}</strong><p className="field-hint">{r.status==="expired"?"Срок запроса истёк":r.status==="rejected"?"Запрос отклонён":r.status==="accepted"?"Готовим беседу автоматически":r.incoming?"Хочет поговорить с тобой":"Ждём подтверждения кота"}</p></div>{r.incoming&&r.status==="pending"&&<div className="account-actions"><button className="button primary" disabled={busy} onClick={()=>decide(r.id,true)}>Принять</button><button className="button secondary" disabled={busy} onClick={()=>decide(r.id,false)}>Отклонить</button></div>}</div>)}
      <button className="button secondary full" disabled={busy} onClick={invite}>Пригласить по ссылке или QR</button>
      <button className="button secondary full" disabled={busy} onClick={logout}>Выйти из аккаунта</button>
      <p className="field-hint">Выход сохраняет существующие беседы на этом устройстве.</p>
    </>}
  </div>;
}
