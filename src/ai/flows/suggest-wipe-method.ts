'use server';

/**
 * @fileOverview This file defines a Genkit flow for suggesting the appropriate data wiping method based on user input.
 *
 * The flow takes into account the type of data to be removed and the desired level of security.
 *
 * @fileOverview AI-powered tool that suggests the appropriate data wiping method based on the type of data they need to remove and their desired level of security.
 * @fileOverview Suggests the best method for the user's needs.
 * - suggestWipeMethod - A function that handles the suggestion of the wipe method.
 * - SuggestWipeMethodInput - The input type for the suggestWipeMethod function.
 * - SuggestWipeMethodOutput - The return type for the suggestWipeMethod function.
 */

import {ai} from '@/ai/genkit';
import {z} from 'genkit';

const SuggestWipeMethodInputSchema = z.object({
  dataType: z
    .string()
    .describe("The type of data the user wants to remove (e.g., personal files, sensitive documents, operating system)."),
  securityLevel: z
    .string()
    .describe("The desired level of security (e.g., low, medium, high)."),
});
export type SuggestWipeMethodInput = z.infer<typeof SuggestWipeMethodInputSchema>;

const SuggestWipeMethodOutputSchema = z.object({
  wipeMethod: z
    .string()
    .describe("The suggested data wiping method (e.g., Single Pass, DoD 3-Pass, Gutmann 35-Pass)."),
  reasoning: z
    .string()
    .describe("The AI's reasoning for suggesting the recommended wipe method, explaining the benefits."),
});
export type SuggestWipeMethodOutput = z.infer<typeof SuggestWipeMethodOutputSchema>;

export async function suggestWipeMethod(input: SuggestWipeMethodInput): Promise<SuggestWipeMethodOutput> {
  return suggestWipeMethodFlow(input);
}

const prompt = ai.definePrompt({
  name: 'suggestWipeMethodPrompt',
  input: {schema: SuggestWipeMethodInputSchema},
  output: {schema: SuggestWipeMethodOutputSchema},
  prompt: `You are an expert in data security and data wiping methods. Based on the user's input about the type of data they want to remove and their desired level of security, you will suggest the most appropriate data wiping method.

  Type of data to remove: {{{dataType}}}
  Desired level of security: {{{securityLevel}}}

  Consider the following data wiping methods:
  - Single Pass: Overwrites the data once with zeros or random characters. Suitable for low-security needs.
  - DoD 3-Pass: A three-pass wiping method that meets the U.S. Department of Defense standards. Suitable for medium-security needs.
  - Gutmann 35-Pass: Overwrites the data 35 times with different patterns. Suitable for high-security needs.

  Based on the user's input, suggest one of the wiping methods and provide a reasoning for why this is the most appropriate method.

  Here is the response format:
  {
    "wipeMethod": "The name of the recommended data wiping method",
    "reasoning": "A detailed explanation of why this method is the most suitable given the user's data type and security needs."
  }`,
});

const suggestWipeMethodFlow = ai.defineFlow(
  {
    name: 'suggestWipeMethodFlow',
    inputSchema: SuggestWipeMethodInputSchema,
    outputSchema: SuggestWipeMethodOutputSchema,
  },
  async input => {
    const {output} = await prompt(input);
    return output!;
  }
);
