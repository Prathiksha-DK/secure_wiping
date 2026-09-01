
'use server';

/**
 * @fileOverview This file defines a Genkit flow for analyzing the result of the Bomber Game.
 *
 * The flow takes the game grid and bomb locations, determines the revealed pattern,
 * and generates a creative, mission-style report based on that pattern with structured output.
 */

import { ai } from '@/ai/genkit';
import { z } from 'zod';

const BomberGameInputSchema = z.object({
  grid: z.array(z.array(z.number())).describe("The entire game grid, a 2D array of 0s and 1s."),
  bombs: z.array(z.array(z.number())).describe("An array of [row, col] coordinates where bombs were placed."),
});
export type BomberGameInput = z.infer<typeof BomberGameInputSchema>;

const BomberGameOutputSchema = z.object({
  patternCategory: z.string().describe("A short classification of the blast pattern, like 'Surgical Strike', 'Cluster Formation', 'Scattered Extraction', or 'Clean Diagonal'."),
  dataAssessment: z.string().describe("An inventive, plausible-sounding purpose for the extracted binary data (e.g., 'Fragments of an encrypted enemy communication key' or 'A partial schematic for a new power core')."),
  missionSuccess: z.enum(["Low", "Medium", "High"]).describe("A rating of the overall success of the data extraction operation. Base this on the number of bombs used vs. the amount of data extracted."),
  recommendation: z.string().describe("A concluding sentence on next steps (e.g., 'Recommend immediate decryption.' or 'Further extraction runs are required to complete the dataset.')."),
});
export type BomberGameOutput = z.infer<typeof BomberGameOutputSchema>;


export async function generateBlastReport(input: BomberGameInput): Promise<BomberGameOutput> {
    
    const { grid, bombs } = input;
    const height = grid.length;
    const width = grid[0]?.length || 0;
    const totalCells = width * height;
    const totalOnes = grid.flat().filter(cell => cell === 1).length;

    const isCellInBombRadius = (row: number, col: number) => {
        return bombs.some(([bombRow, bombCol]) => 
        Math.abs(row - bombRow) <= 1 && Math.abs(col - bombCol) <= 1
        );
    };

    let revealedPattern = 'No data extracted.';
    let extractedDataCount = 0;
    if (width > 0) {
        revealedPattern = grid.map((row, r) => 
            row.map((cell, c) => {
                if (isCellInBombRadius(r,c)) {
                    extractedDataCount++;
                    return cell;
                }
                return '-';
            }).join('')
        ).join('\n');
    }

    const onesExtracted = grid.flat().filter((cell, i) => {
        const row = Math.floor(i / width);
        const col = i % width;
        return cell === 1 && isCellInBombRadius(row, col);
    }).length;

    const extractionEfficiency = totalOnes > 0 ? (onesExtracted / totalOnes) : 0;

    return generateBlastReportFlow({
        pattern: revealedPattern,
        bombsUsed: bombs.length,
        gridSize: `${width}x${height}`,
        extractionEfficiency: parseFloat(extractionEfficiency.toFixed(2)),
    });
}

const prompt = ai.definePrompt({
  name: 'generateBlastReportPrompt',
  input: { schema: z.object({ pattern: z.string(), bombsUsed: z.number(), gridSize: z.string(), extractionEfficiency: z.number() }) },
  output: { schema: BomberGameOutputSchema },
  prompt: `You are a "Blast Pattern Analyst" for an elite data extraction squad.
Your mission is to analyze the provided data grid, which shows the results of a "bombing run" on a secure data fortress.

- The grid consists of '0's, '1's, and '-' characters.
- '0' and '1' represent the binary data fragments successfully extracted.
- '-' represents areas that were not hit and from which no data was recovered.
- You used {{{bombsUsed}}} bombs on a {{{gridSize}}} grid for this operation.
- The target data extraction efficiency was {{extractionEfficiency}}. (1.0 means 100% of target data was extracted).

Your task is to analyze the extracted data pattern and generate a structured mission report. Be creative and thematic, as if you are in a spy or sci-fi movie. A high extraction efficiency with few bombs should result in a high success rating.

Here is the extracted data pattern:
---
{{{pattern}}}
---

Based on the pattern, bombs used, grid size, and efficiency, provide your analysis in the required JSON format.`,
});

const generateBlastReportFlow = ai.defineFlow(
  {
    name: 'generateBlastReportFlow',
    inputSchema: z.object({ pattern: z.string(), bombsUsed: z.number(), gridSize: z.string(), extractionEfficiency: z.number() }),
    outputSchema: BomberGameOutputSchema,
  },
  async ({ pattern, bombsUsed, gridSize, extractionEfficiency }) => {
    const { output } = await prompt({ pattern, bombsUsed, gridSize, extractionEfficiency });
    return output!;
  }
);
