import { Logger, Module } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';
import { carriesBody, createApiApplication, refuseNonJsonBodies } from '../../src/bootstrap/api-application';

/**
 * Le bord JSON SEULEMENT (étape 3bis), en unité. La matrice complète, sur le vrai
 * main.ts et de vraies requêtes, vit dans tests/bootstrap/main-boot.spec.ts.
 */
function request(headers: Record<string, string>, body?: unknown): Request {
  return { headers, body } as unknown as Request;
}

function run(req: Request): { status: number | null; nexted: number } {
  let status: number | null = null;
  let nexted = 0;
  const res = {
    status(code: number) {
      status = code;
      return this;
    },
    json() {
      return this;
    },
  } as unknown as Response;
  const next: NextFunction = () => {
    nexted += 1;
  };
  refuseNonJsonBodies(req, res, next);
  return { status, nexted };
}

describe('carriesBody — un corps NON VIDE', () => {
  test.each([
    [{}, false],
    [{ 'content-length': '0' }, false],
    [{ 'content-length': '12' }, true],
    [{ 'transfer-encoding': 'chunked' }, true],
    [{ 'content-length': 'abc' }, false],
  ])('%j ⇒ %s', (headers, expected) => {
    expect(carriesBody(request(headers))).toBe(expected);
  });
});

describe('refuseNonJsonBodies — un refus PROPRE, jamais une exception', () => {
  test('un corps que le lecteur JSON a pris passe tel quel', () => {
    const req = request({ 'content-length': '20' }, { identifier: 'x' });
    expect(run(req)).toEqual({ status: null, nexted: 1 });
    expect(req.body).toEqual({ identifier: 'x' });
  });

  test('un corps NON VIDE que le lecteur JSON n’a pas pris ⇒ 415, et la route n’est jamais atteinte', () => {
    expect(run(request({ 'content-length': '37', 'content-type': 'application/x-www-form-urlencoded' }))).toEqual({
      status: 415,
      nexted: 0,
    });
    expect(run(request({ 'transfer-encoding': 'chunked', 'content-type': 'text/plain' }))).toEqual({
      status: 415,
      nexted: 0,
    });
  });

  test('aucun corps, ou un corps vide ⇒ {} : le contrôleur rend son propre refus', () => {
    const cases: Record<string, string>[] = [{}, { 'content-length': '0' }];
    for (const headers of cases) {
      const req = request(headers);
      expect(run(req)).toEqual({ status: null, nexted: 1 });
      expect(req.body).toEqual({});
    }
  });
});

@Module({})
class EmptyModule {}

describe('la chaîne de lecteurs — UN seul lecteur de corps, le JSON, avant le refus propre', () => {
  test('après init(), là où NestJS installe ses lecteurs par défaut : aucun lecteur de formulaires', async () => {
    // Le test du démarrage ne peut PAS voir un lecteur de formulaires revenu : NestJS
    // l'installe dans init(), donc APRÈS le refus propre, qui refuse le formulaire
    // le premier — mais qs serait de nouveau dans la chaîne. Seule la structure le
    // montre (mesuré le 03/10/2026 : sans ce test, retirer bodyParser:false ne
    // faisait rougir aucun test).
    Logger.overrideLogger(false);
    const app = await createApiApplication({ module: EmptyModule });
    try {
      await app.init();
      const { router } = app.getHttpAdapter().getInstance() as { router: { stack: { name: string }[] } };
      const names = router.stack.map((layer) => layer.name);
      expect(names.filter((name) => name.endsWith('Parser'))).toEqual(['jsonParser']);
      expect(names.indexOf('refuseNonJsonBodies')).toBeGreaterThan(names.indexOf('jsonParser'));
    } finally {
      await app.close();
    }
  });
});
