/* Category slugs are kebab-case on disk (`ssh-remote-access`, `rootkit-malware`) because
   that's the directory name under rules/. Title-casing them blindly produces "Ssh Remote
   Access", which reads as a typo in a tool aimed at people who type `ssh` daily. These are the
   slugs whose casing a naive `\b\w` capitalise gets wrong. */
const ACRONYMS: Record<string, string> = {
  ssh: "SSH",
};

/** `ssh-remote-access` → `SSH Remote Access`. */
export function categoryLabel(category: string): string {
  return category
    .split("-")
    .map((word) => ACRONYMS[word] ?? word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}
