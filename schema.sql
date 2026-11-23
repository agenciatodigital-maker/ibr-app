-- IBR App: esquema do banco (Supabase). Rodar uma vez no SQL Editor.

create table if not exists public.perfis (
  id uuid primary key references auth.users(id) on delete cascade,
  tel text not null unique,
  papel text not null default 'membro' check (papel in ('membro','lider','comunicacao','colegiado','admin')),
  status text not null default 'pendente' check (status in ('pendente','ativo')),
  lider_de text[] not null default '{}',
  novo boolean not null default false,
  dados jsonb not null default '{}'::jsonb,
  criado timestamptz not null default now()
);

create table if not exists public.registros (
  id uuid primary key default gen_random_uuid(),
  colecao text not null check (colecao in ('devocionais','avisos','visitas','recs','pedidos','albuns','financas','vinculos')),
  chave text,
  dados jsonb not null default '{}'::jsonb,
  autor uuid default auth.uid(),
  criado timestamptz not null default now()
);
create index if not exists registros_colecao_idx on public.registros (colecao, criado desc);
create unique index if not exists registros_chave_idx on public.registros (colecao, chave) where chave is not null;

alter table public.perfis enable row level security;
alter table public.registros enable row level security;

-- Funções auxiliares (security definer evita recursão nas políticas)
create or replace function public.meu_papel() returns text
language sql stable security definer set search_path = public as $$
  select papel from public.perfis where id = auth.uid() and status = 'ativo'
$$;

create or replace function public.sou_ativo() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.perfis where id = auth.uid() and status = 'ativo')
$$;

-- Perfis ----------------------------------------------------------------
drop policy if exists perfis_ver on public.perfis;
create policy perfis_ver on public.perfis for select to authenticated
  using (id = auth.uid() or public.meu_papel() in ('admin','colegiado','lider'));

drop policy if exists perfis_criar on public.perfis;
create policy perfis_criar on public.perfis for insert to authenticated
  with check (id = auth.uid() and papel = 'membro' and status = 'pendente' and not novo and lider_de = '{}');

drop policy if exists perfis_editar_proprio on public.perfis;
create policy perfis_editar_proprio on public.perfis for update to authenticated
  using (id = auth.uid()) with check (id = auth.uid());

drop policy if exists perfis_admin_edita on public.perfis;
create policy perfis_admin_edita on public.perfis for update to authenticated
  using (public.meu_papel() = 'admin') with check (public.meu_papel() = 'admin');

-- Quem não é admin não pode mudar papel, status ou liderança
create or replace function public.proteger_perfil() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if coalesce(public.meu_papel(), '') <> 'admin' then
    new.papel := old.papel; new.status := old.status; new.lider_de := old.lider_de;
    new.novo := old.novo; new.tel := old.tel;
  end if;
  return new;
end $$;
drop trigger if exists proteger_perfil_trg on public.perfis;
create trigger proteger_perfil_trg before update on public.perfis
  for each row execute function public.proteger_perfil();

-- Lista para membros ativos: sem endereço, profissão, batismo e telefone oculto
create or replace view public.perfis_lista with (security_invoker = false) as
select p.id,
  case when p.dados->>'telVisivel' = 'nao' then null else p.tel end as tel,
  p.papel, p.status, p.lider_de, p.novo, p.criado,
  p.dados - 'endereco' - 'profissao' - 'batismoData' - 'batismoLocal' - 'tel2' - 'casamento' as dados
from public.perfis p
where p.status = 'ativo' and public.sou_ativo();

-- Apagar cadastro (admin): remove também o login
create or replace function public.admin_excluir_usuario(alvo uuid) returns void
language plpgsql security definer set search_path = public, auth as $$
begin
  if public.meu_papel() <> 'admin' then raise exception 'apenas administrador'; end if;
  if alvo = auth.uid() then raise exception 'não é possível excluir a si mesmo'; end if;
  delete from auth.users where id = alvo;
end $$;

-- Registros --------------------------------------------------------------
-- leitura
drop policy if exists reg_ver on public.registros;
create policy reg_ver on public.registros for select to authenticated using (
  public.sou_ativo() and (
    colecao in ('devocionais','avisos','albuns','financas')
    or (colecao = 'recs' and (dados->>'status' = 'aprovada' or autor = auth.uid() or public.meu_papel() = 'admin'))
    or (colecao = 'visitas' and public.meu_papel() in ('admin','colegiado','lider'))
    or (colecao in ('pedidos','vinculos') and public.meu_papel() = 'admin')
  )
);

-- escrita (insert / update / delete) por coleção e papel
create or replace function public.pode_escrever(col text) returns boolean
language sql stable security definer set search_path = public as $$
  select case col
    when 'devocionais' then public.meu_papel() in ('admin','colegiado')
    when 'avisos'      then public.meu_papel() in ('admin','colegiado','lider','comunicacao')
    when 'albuns'      then public.meu_papel() in ('admin','comunicacao')
    when 'visitas'     then public.meu_papel() in ('admin','colegiado','lider')
    when 'financas'    then public.meu_papel() = 'admin'
    when 'vinculos'    then public.meu_papel() = 'admin'
    when 'recs'        then public.sou_ativo()
    when 'pedidos'     then public.sou_ativo()
    else false end
$$;

drop policy if exists reg_inserir on public.registros;
create policy reg_inserir on public.registros for insert to authenticated
  with check (public.pode_escrever(colecao) and autor = auth.uid()
    and (colecao <> 'recs' or public.meu_papel() = 'admin' or dados->>'status' = 'pendente'));

drop policy if exists reg_editar on public.registros;
create policy reg_editar on public.registros for update to authenticated
  using (public.pode_escrever(colecao) and (colecao not in ('recs','pedidos') or public.meu_papel() = 'admin'))
  with check (public.pode_escrever(colecao));

drop policy if exists reg_apagar on public.registros;
create policy reg_apagar on public.registros for delete to authenticated
  using (public.pode_escrever(colecao) and (colecao not in ('recs','pedidos') or public.meu_papel() = 'admin'));

-- Acesso da API (o projeto foi criado sem concessão automática)
revoke all on public.perfis, public.registros from anon;
grant select, insert, update on public.perfis to authenticated;
grant select, insert, update, delete on public.registros to authenticated;
grant select on public.perfis_lista to authenticated;
grant execute on function public.admin_excluir_usuario(uuid) to authenticated;
