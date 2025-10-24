import * as dotenv from 'dotenv';
import { resolve } from 'path';

// Load environment variables from .env file for e2e tests
dotenv.config({ path: resolve(__dirname, '../.env') });
