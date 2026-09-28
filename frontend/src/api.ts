/* 서버 호출. 실패는 삼키지 않고 화면까지 올린다. */
export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(path, init);
  const text = await r.text();
  let data: unknown;
  try { data = JSON.parse(text); } catch { data = {detail: text}; }
  if (!r.ok) {
    const d = data as {detail?: string};
    throw new Error(d.detail ?? `요청이 실패했습니다 (${r.status})`);
  }
  return data as T;
}

export const post = <T,>(path: string, body: unknown): Promise<T> =>
  api<T>(path, {method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(body)});

/** 로딩·오류·데이터 셋을 한 번에 다루는 작은 훅 */
import {useEffect, useState, useCallback} from 'react';

export function useApi<T>(path: string | null, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const reload = useCallback(() => {
    if (!path) return;
    setData(null); setError(null);
    api<T>(path).then(setData).catch(setError);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, ...deps]);
  useEffect(reload, [reload]);
  return {data, error, reload};
}
