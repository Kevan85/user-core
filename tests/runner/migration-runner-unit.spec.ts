import {
  assertUniquePrefixes,
  checksumOf,
  isSelfTransactional,
  normalizeLf,
} from '../../scripts/migrate';

// Tests unitaires purs (sans base) des mécanismes du runner.
describe('Détection auto-transactionnelle', () => {
  test('BEGIN en premier token → auto-transactionnel', () => {
    expect(isSelfTransactional('BEGIN;\nCREATE TABLE t (id int);\nCOMMIT;\n')).toBe(true);
  });

  test('BEGIN précédé de commentaires et lignes vides → détecté quand même', () => {
    expect(isSelfTransactional('-- en-tête\n\n-- suite\nBEGIN;\nSELECT 1;\nCOMMIT;\n')).toBe(true);
  });

  test('begin minuscule → détecté (insensible à la casse)', () => {
    expect(isSelfTransactional('begin;\nselect 1;\ncommit;\n')).toBe(true);
  });

  test('BEGIN de bloc plpgsql (DO $$ … BEGIN) → PAS auto-transactionnel (cas 001)', () => {
    expect(isSelfTransactional('DO $$\nBEGIN\n  PERFORM 1;\nEND\n$$;\n')).toBe(false);
  });

  test('CREATE FUNCTION contenant BEGIN plpgsql → PAS auto-transactionnel', () => {
    expect(
      isSelfTransactional(
        'CREATE OR REPLACE FUNCTION f() RETURNS trigger AS $$\nBEGIN\n  RETURN NEW;\nEND;\n$$ LANGUAGE plpgsql;\n',
      ),
    ).toBe(false);
  });

  test('fichier ne commençant pas par BEGIN → enveloppé par le runner', () => {
    expect(isSelfTransactional('CREATE TABLE t (id int);\n')).toBe(false);
  });
});

describe('Checksum sur contenu normalisé LF', () => {
  test('CRLF (poste Windows) et LF (CI Linux) donnent le MÊME checksum', () => {
    const lf = '-- migration\nCREATE TABLE t (id int);\n';
    const crlf = lf.replace(/\n/g, '\r\n');
    expect(checksumOf(normalizeLf(crlf))).toBe(checksumOf(normalizeLf(lf)));
  });

  test('un contenu réellement différent donne un checksum différent', () => {
    expect(checksumOf('a\n')).not.toBe(checksumOf('b\n'));
  });
});

describe('Unicité des numéros de migration', () => {
  test('deux fichiers avec le même préfixe → refus net', () => {
    expect(() => assertUniquePrefixes(['001_a.sql', '001_b.sql'])).toThrow(
      /Numéro de migration dupliqué : 001/,
    );
  });

  test('préfixes tous distincts → accepté', () => {
    expect(() => assertUniquePrefixes(['001_a.sql', '002_b.sql'])).not.toThrow();
  });
});
