const dns = require("dns").promises;

const MAX_DOMAINS = 50;
const MAX_SUBDOMAINS_PER_DOMAIN = 100;

function isValidDomain(domain) {
  const regex = /^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$/;
  return regex.test(domain);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchSubdomains(domain) {
  const apiKey = process.env.VT_API_KEY;

  if (!apiKey) {
    throw new Error("Missing VT_API_KEY environment variable.");
  }

  let url = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}/subdomains`;
  const subdomains = [];

  while (url && subdomains.length < MAX_SUBDOMAINS_PER_DOMAIN) {
    const response = await fetch(url, {
      headers: {
        "x-apikey": apiKey
      }
    });

    if (response.status === 429) {
      throw new Error("VirusTotal rate limit reached. Try again later.");
    }

    if (!response.ok) {
      throw new Error(`VirusTotal error for ${domain}: HTTP ${response.status}`);
    }

    const data = await response.json();

    for (const item of data.data || []) {
      if (item.id && subdomains.length < MAX_SUBDOMAINS_PER_DOMAIN) {
        subdomains.push(item.id);
      }
    }

    url = data.links?.next || null;

    await sleep(300);
  }

  return [...new Set(subdomains)].sort();
}

async function hasSpfRecord(subdomain) {
  try {
    const records = await dns.resolveTxt(subdomain);

    return records.some((recordParts) => {
      const txt = recordParts.join("");
      return txt.toLowerCase().startsWith("v=spf1");
    });
  } catch {
    return false;
  }
}

async function checkSpfInBatches(subdomains, batchSize = 20) {
  const spfSubdomains = [];

  for (let i = 0; i < subdomains.length; i += batchSize) {
    const batch = subdomains.slice(i, i + batchSize);

    const checks = await Promise.all(
      batch.map(async (subdomain) => {
        const hasSpf = await hasSpfRecord(subdomain);

        if (hasSpf) {
          return subdomain;
        }

        return null;
      })
    );

    for (const result of checks) {
      if (result) {
        spfSubdomains.push(result);
      }
    }
  }

  return spfSubdomains.sort();
}

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({
      error: "Method not allowed."
    });
  }

  try {
    const { domains } = req.body;

    if (!Array.isArray(domains) || domains.length === 0) {
      return res.status(400).json({
        error: "Please provide a list of domains."
      });
    }

    const cleanDomains = [
      ...new Set(
        domains
          .map((d) => String(d).trim().toLowerCase())
          .filter(Boolean)
      )
    ];

    if (cleanDomains.length > MAX_DOMAINS) {
      return res.status(400).json({
        error: `Maximum ${MAX_DOMAINS} domains allowed per scan.`
      });
    }

    for (const domain of cleanDomains) {
      if (!isValidDomain(domain)) {
        return res.status(400).json({
          error: `Invalid domain: ${domain}`
        });
      }
    }

    const results = [];

    for (const domain of cleanDomains) {
      const subdomains = await fetchSubdomains(domain);
      const spfSubdomains = await checkSpfInBatches(subdomains, 20);

      results.push({
        domain,
        checkedSubdomains: subdomains.length,
        spfSubdomains
      });

      await sleep(500);
    }

    return res.status(200).json({
      results
    });
  } catch (error) {
    return res.status(500).json({
      error: error.message || "Internal server error."
    });
  }
};
