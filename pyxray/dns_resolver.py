import aiohttp
import aiodns
import logging

class DoHResolver:
    def __init__(self):
        self.logger = logging.getLogger("doh_resolver")
        self.session = aiohttp.ClientSession()
        self.resolver = aiodns.DNSResolver()
    
    async def resolve(self, domain: str):
        """Resolve domain using DNS-over-HTTPS"""
        try:
            async with self.session.get(
                f"https://cloudflare-dns.com/dns-query?name={domain}&type=A",
                headers={"Accept": "application/dns-json"}
            ) as response:
                data = await response.json()
                return data.get('Answer', [])[0]['data']
        except Exception as e:
            self.logger.warning(f"DoH failed: {str(e)}, falling back to system DNS")
            return await self.resolver.query(domain, 'A')