
import { NextResponse } from 'next/server';
import { z } from 'zod';

const wipeMethodRequestSchema = z.object({
  device: z.string(),
});

/**
 * Determines the appropriate wipe method for a given device.
 * In a real-world scenario, this could involve checking a database
 * or a device management policy.
 */
export async function POST(request: Request) {
  try {
    const json = await request.json();
    const parsed = wipeMethodRequestSchema.safeParse(json);

    if (!parsed.success) {
      return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
    }

    const { device } = parsed.data;

    // This is where you would put your complex logic.
    // For example, based on device type, security policy, etc.
    // For this example, we'll use a simple logic:
    // If the device is our primary, most sensitive SSD, we use the strongest method.
    // Otherwise, we use a standard method.
    let method;
    if (device.includes('Primary SSD')) {
      method = 'encrypt-and-wipe';
    } else if (device.includes('HDD')) {
      method = 'dod'; // DoD 3-Pass is good for HDDs
    } else {
      method = 'single'; // Single pass for less sensitive devices like USBs
    }

    return NextResponse.json({ method });

  } catch (error) {
    console.error("Error in get-wipe-method:", error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}

    