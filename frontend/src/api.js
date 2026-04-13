export async function getFindings() {
  const response = await fetch("https://a1f5aptpxk.execute-api.ap-south-1.amazonaws.com/dev/findings");
  const text = await response.text(); // read as plain text first
  console.log("Raw response from API:", text);

  try {
    return JSON.parse(text);
  } catch (err) {
    console.error("❌ Failed to parse JSON:", err);
    throw new Error("Invalid JSON returned from API");
  }
}
