# Virtual / Remote Wipe: Tailscale Private Network Setup

This guide explains how to configure the Virtual / Remote Wipe module to communicate securely over a Tailscale private network, allowing you to manage and sanitize storage devices on a friend's authorized computer.

> **Note:** Tailscale provides private connectivity between authorized development machines. It does not bypass or replace the application's authentication, user login, owner authorization, or audit logging mechanisms.

## Architecture Overview

* **Computer A (Administrator):** Runs the Next.js Admin Dashboard and the Flask API backend.
* **Computer B (Friend):** Runs the lightweight Python Remote Sanitization Agent.

Both computers must be connected to the same Tailscale network.

---

## Step 1: Install and Configure Tailscale

1. **Install Tailscale** on both Computer A (Administrator) and Computer B (Friend). Download from [tailscale.com](https://tailscale.com/).
2. **Authenticate** both machines into the same authorized Tailscale network (your private Tailnet).
3. **Find the Tailscale IP of Computer A**. 
   * On Computer A, open a terminal and run `tailscale ip -4`.
   * Note this IP address (e.g., `100.95.12.34`).

---

## Step 2: Start the Backend (Computer A)

The Flask backend is already configured to bind to all interfaces (`0.0.0.0`), which automatically includes your Tailscale interface.

1. On Computer A, start the main backend API if it isn't running:
   ```powershell
   cd backend
   python app.py
   ```
   *(Ensure it starts on port 9758).*

2. Start the Next.js Dashboard:
   ```powershell
   npm run dev
   ```

---

## Step 3: Configure and Start the Agent (Computer B)

On the friend's computer, configure the Remote Agent to connect to Computer A's Tailscale IP instead of `localhost`.

1. Open a terminal (PowerShell or Command Prompt).
2. Set the `REMOTE_WIPE_SERVER_URL` environment variable using Computer A's Tailscale IP:

   **Windows (PowerShell):**
   ```powershell
   $env:REMOTE_WIPE_SERVER_URL="http://<COMPUTER_A_TAILSCALE_IP>:9758"
   ```
   
   **Windows (CMD):**
   ```cmd
   set REMOTE_WIPE_SERVER_URL=http://<COMPUTER_A_TAILSCALE_IP>:9758
   ```

   **Linux / macOS:**
   ```bash
   export REMOTE_WIPE_SERVER_URL="http://<COMPUTER_A_TAILSCALE_IP>:9758"
   ```

3. Run the Remote Agent:
   ```powershell
   cd remote_wipe_agent
   python agent.py
   ```

### Troubleshooting Connection
If the agent cannot reach the backend, it will display a `DIAGNOSTIC: CONNECTION FAILURE` message. Verify that:
* Both machines are online in the Tailscale admin console.
* You did not include a trailing slash in the environment variable.
* Computer A's firewall is allowing inbound traffic on port `9758` over the Tailscale interface.

---

## Step 4: Verification and Workflow Testing

1. **Verify Dashboard Appearance**: Open the Next.js dashboard on Computer A (`http://localhost:3000/remote-wipe`). The friend's computer should now appear in the **My Remote Computers** list as "Online".
2. **Verify Device Isolation**: Click on the friend's computer. You should strictly see only the physical storage devices connected to Computer B (e.g., Disk 0, Disk 1). You should never see Computer A's devices listed under Computer B.
3. **Test Owner Authorization**: 
   * Select one of Computer B's devices and click **Send Owner Authorization Request**.
   * A consent popup dialog will appear on Computer B's screen, warning the user about destructive data operations.
   * Have the friend click **APPROVE**.
4. **Test the Workflow (DRY-RUN MODE)**:
   * Once approved, click **Start Remote Wipe** on Computer A.
   * Observe the pipeline safely simulating the execution of the existing sanitization strategies. 
   * Actual destructive wiping is currently disabled in the configuration to keep testing safe.
