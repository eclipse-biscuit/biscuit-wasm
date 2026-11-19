import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";

const rootDir = new URL("../", import.meta.url);

function read(relativePath) {
  return readFileSync(new URL(relativePath, rootDir), "utf8");
}

function write(relativePath, contents) {
  writeFileSync(new URL(relativePath, rootDir), contents);
}

function withTrailingNewline(contents) {
  return contents.endsWith("\n") ? contents : `${contents}\n`;
}

function listSnippetModules(dirPath) {
  const moduleSnippetDir = new URL(dirPath, rootDir);
  const stack = [moduleSnippetDir.pathname];
  const modulePaths = [];

  while (stack.length > 0) {
    const current = stack.pop();
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const entryPath = join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(entryPath);
        continue;
      }

      if (!entry.isFile() || !entry.name.endsWith(".js")) {
        continue;
      }

      const relPath = relative(moduleSnippetDir.pathname, entryPath).replaceAll(
        "\\",
        "/"
      );
      modulePaths.push(`./snippets/${relPath}`);
    }
  }

  return modulePaths.sort();
}

function renderTemplate(relativePath, replacements) {
  let contents = read(relativePath);
  for (const [token, value] of Object.entries(replacements)) {
    contents = contents.replaceAll(token, value);
  }
  return contents;
}

const helperSnippets = [
  read("snippets/biscuit-express.js"),
  read("snippets/tagged-templates.js"),
].map(withTrailingNewline);
const helperDefinitions = [
  read("snippets/definitions/biscuit-express.d.ts"),
  read("snippets/definitions/tagged-templates.d.ts"),
].map(withTrailingNewline);
const snippetModules = JSON.stringify(
  listSnippetModules("module/snippets"),
  null,
  2
);

const biscuitJs =
  withTrailingNewline(read("module/biscuit.js")) + helperSnippets.join("\n");
write("module/biscuit.js", biscuitJs);

const biscuitDts =
  withTrailingNewline(read("module/biscuit.d.ts")) +
  helperDefinitions.join("\n");
write("module/biscuit.d.ts", biscuitDts);

const initJs = renderTemplate("snippets/runtime/init.js", {
  __SNIPPET_MODULES__: snippetModules,
});
write("module/init.js", withTrailingNewline(initJs));

const syncJs =
  withTrailingNewline(read("snippets/runtime/sync.js")) +
  helperSnippets.join("\n");
write("module/sync.js", syncJs);

const syncDts =
  withTrailingNewline(read("snippets/definitions/sync.d.ts")) +
  withTrailingNewline(read("module/biscuit.d.ts"));
write("module/sync.d.ts", syncDts);

const workerdJs =
  withTrailingNewline(read("snippets/runtime/workerd.js")) +
  helperSnippets.join("\n");
write("module/workerd.js", workerdJs);
