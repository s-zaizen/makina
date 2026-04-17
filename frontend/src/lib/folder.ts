import type { FileNode, Language } from "./types";

const EXT_TO_LANG: Record<string, Language> = {
  py: "python", pyw: "python",
  js: "javascript", mjs: "javascript", cjs: "javascript",
  ts: "typescript", tsx: "typescript",
  rs: "rust",
  go: "go",
  java: "java", kt: "java", groovy: "java",
  rb: "ruby",
  c: "c", h: "c",
  cpp: "cpp", cc: "cpp", cxx: "cpp", hpp: "cpp",
};

const SKIP_DIRS = new Set(["node_modules", ".git", ".next", "dist", "build", "target", "__pycache__", ".venv", "venv"]);

export function langFromFilename(name: string): Language | undefined {
  const ext = name.split(".").pop()?.toLowerCase();
  return ext ? EXT_TO_LANG[ext] : undefined;
}

function readAllEntries(reader: FileSystemDirectoryReader): Promise<FileSystemEntry[]> {
  return new Promise((resolve, reject) => {
    const results: FileSystemEntry[] = [];
    const readBatch = () => {
      reader.readEntries((entries) => {
        if (entries.length === 0) {
          resolve(results);
        } else {
          results.push(...entries);
          readBatch();
        }
      }, reject);
    };
    readBatch();
  });
}

async function buildTree(entry: FileSystemDirectoryEntry, path: string): Promise<FileNode> {
  const node: FileNode = { name: entry.name, path, type: "dir", children: [] };
  const reader = entry.createReader();
  const entries = await readAllEntries(reader);

  const children = await Promise.all(
    entries
      .filter((e) => !(e.isDirectory && SKIP_DIRS.has(e.name)))
      .map(async (e): Promise<FileNode | null> => {
        const childPath = `${path}/${e.name}`;
        if (e.isDirectory) {
          return buildTree(e as FileSystemDirectoryEntry, childPath);
        } else {
          const lang = langFromFilename(e.name);
          if (!lang) return null;
          const content = await new Promise<string>((res, rej) => {
            (e as FileSystemFileEntry).file((f) => {
              const reader = new FileReader();
              reader.onload = () => res(reader.result as string);
              reader.onerror = rej;
              reader.readAsText(f);
            }, rej);
          });
          return { name: e.name, path: childPath, type: "file", language: lang, content };
        }
      }),
  );

  node.children = children.filter((c): c is FileNode => c !== null);
  // Drop empty directories
  node.children = node.children.filter((c) => c.type === "file" || (c.children?.length ?? 0) > 0);
  return node;
}

export async function readFolder(item: DataTransferItem): Promise<FileNode | null> {
  const entry = item.webkitGetAsEntry();
  if (!entry) return null;
  if (entry.isDirectory) {
    return buildTree(entry as FileSystemDirectoryEntry, entry.name);
  }
  // Single file drop
  const lang = langFromFilename(entry.name);
  if (!lang) return null;
  const content = await new Promise<string>((res, rej) => {
    (entry as FileSystemFileEntry).file((f) => {
      const reader = new FileReader();
      reader.onload = () => res(reader.result as string);
      reader.onerror = rej;
      reader.readAsText(f);
    }, rej);
  });
  return { name: entry.name, path: entry.name, type: "file", language: lang, content };
}

export function flatFiles(node: FileNode): FileNode[] {
  if (node.type === "file") return [node];
  return (node.children ?? []).flatMap(flatFiles);
}

export function countFiles(node: FileNode): number {
  return flatFiles(node).length;
}
