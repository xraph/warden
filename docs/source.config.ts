import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { rehypeCodeDefaultOptions } from "fumadocs-core/mdx-plugins";
import { metaSchema, pageSchema } from "fumadocs-core/source/schema";
import { defineConfig, defineDocs } from "fumadocs-mdx/config";

// You can customise Zod schemas for frontmatter and `meta.json` here
// see https://fumadocs.dev/docs/mdx/collections
export const docs = defineDocs({
  dir: "content/docs",
  docs: {
    schema: pageSchema,
    postprocess: {
      includeProcessedMarkdown: true,
    },
  },
  meta: {
    schema: metaSchema,
  },
});

// Load the canonical TextMate grammar that ships with the Warden repo
// (editor/warden.tmLanguage.json). Reading at build time avoids the
// rootDir / includes friction of a TS JSON import for a file that lives
// outside the docs/ project. The grammar already has "scopeName":
// "source.warden" and "fileTypes": ["warden"]; we override "name" to
// match the lowercase code-fence identifier ```warden so Shiki picks it
// up for the right blocks.
//
// Resolved from process.cwd() (the docs/ directory under pnpm scripts)
// so it doesn't depend on where fumadocs-mdx writes its compiled
// .source/source.config.mjs.
const wardenGrammar = JSON.parse(
  readFileSync(
    resolve(process.cwd(), "../editor/warden.tmLanguage.json"),
    "utf8",
  ),
);

export default defineConfig({
  mdxOptions: {
    rehypeCodeOptions: {
      ...rehypeCodeDefaultOptions,
      // Unknown languages (e.g. `ebnf`, niche grammars not in the Shiki
      // bundle) fall back to plain-text rather than failing the build.
      // Catches typos in code fences; intentional new languages should
      // still register a grammar via langs below.
      fallbackLanguage: "text",
      langs: [
        ...(rehypeCodeDefaultOptions.langs ?? []),
        {
          ...wardenGrammar,
          name: "warden",
        },
      ],
    },
  },
});
