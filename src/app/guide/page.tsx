import { redirect } from "next/navigation";

export default function LegacyGuidePage(): never {
  redirect("/docs");
}
