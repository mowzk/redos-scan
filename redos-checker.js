const fs = require('fs');
const path = require('path');
const { check } = require('recheck');

const regexRegex = /\/(\\\/|[^*\/\n\r])(\\\*[^/]|[^\/\n\r])*\/[gimyus]{0,6}(?=\s*(;|,|\)|\]|\}|$))/g;
const fileExtensions = ['.js', '.ts'];

let results = {};

function scanDir(sourcePath) {
  fs.readdir(sourcePath, { withFileTypes: true }, (err, dirents) => {
    if (err) {
      console.error(err);
      return;
    }

    for (const dirent of dirents) {
      const res = path.resolve(sourcePath, dirent.name);
      if (dirent.isDirectory()) {
        scanDir(res);
      } else if (fileExtensions.includes(path.extname(res))) {
        scanFileForRegex(res);
      }
    }
  });
}

function scanFileForRegex(filePath) {
  fs.readFile(filePath, 'utf8', async (err, data) => {
    if (err) {
      console.error(err);
      return;
    }

    // Split new lines so we can collect line info
    const lines = data.split('\n');
    for (let i = 0; i < lines.length; i++) {
      let match;
      while ((match = regexRegex.exec(lines[i])) !== null) {
        const result = await testRegex(match[0]);
        if (result.status === 'vulnerable') {
          if (!results[filePath]) {
            results[filePath] = [];
          }

          results[filePath].push({ regex: match[0], line: i + 1 });
        }
      }
    }
  });
}

function extract(input) {
  if (!input.startsWith("/")) return null;

  var lastSlashPos = input.lastIndexOf('/');
  if (lastSlashPos === 0) return null;

  return {
    source: input.slice(1, lastSlashPos),
    flags: input.slice(lastSlashPos + 1),
  };
}

async function testRegex(input) {
  const extracted = extract(input);
  if (extracted === null) {
    return null;
  }

  const { source, flags } = extracted;

  return await check(source, flags);
}

const sourcePath = process.argv[2];
if (!sourcePath) {
  console.error("Please provide a source path.");
  process.exit(1);
}

scanDir(sourcePath);

process.on('exit', () => {
  console.log(results);
});