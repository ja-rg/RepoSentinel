import { $ } from 'bun';
import { tmpdir } from 'os';

const dir = tmpdir();
const lorem = await $`cat .env`;
const file = await Bun.write(`${dir}/hello.txt`, lorem.text());
console.log(`File created at: ${file}`);