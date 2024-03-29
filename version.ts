/** `version` managed by https://deno.land/x/land/publish. */
export const VERSION = "0.3.0";

/** `prepublish` will be invoked before publish, return `false` to prevent the publish. */
export async function prepublish(version: string) {
  const readme = await Deno.readTextFile("./README.md");

  await Deno.writeTextFile(
    "./README.md",
    readme.replace(
      /\/\/deno\.land\/x\/otp@[\d\.]+\//,
      `//deno.land/x/otp@${version}/`,
    ),
  );
}

/** `postpublish` will be invoked after published */
export async function postpublish(version: string) {
  await console.log("Upgraded to: ", version);
}
