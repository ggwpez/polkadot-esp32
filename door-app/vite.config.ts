import { defineConfig } from 'vite';
import app from './polkadot-app-deploy.config.ts';
export default defineConfig({ base: './', define: { __APP_VERSION__: JSON.stringify(app.executables[0].appVersion.join('.')) }, build: { target: 'es2022' } });
