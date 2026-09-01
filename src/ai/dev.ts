'use server';
import { config } from 'dotenv';
config();

import '@/ai/flows/suggest-wipe-method.ts';
import '@/ai/flows/generate-blast-report.ts';
