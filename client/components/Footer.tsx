import { Link } from "react-router-dom";

const footerColumns = [
  {
    title: "Our product",
    links: ["Contact Us", "Get Support", "How It Works", "ToS | Privacy Notice", "Blog | Releases"],
  },
  {
    title: "Community",
    links: ["Join Community", "Vote and Comment", "Contributors", "Top Users", "Community Buzz"],
  },
  {
    title: "Tools",
    links: ["API Scripts", "YARA", "Desktop Apps", "Browser Extensions", "Mobile App"],
  },
  {
    title: "Premium Services",
    links: ["Get a demo", "Intelligence", "Hunting", "Graph", "API v3 | v2"],
  },
  {
    title: "Documentation",
    links: ["Searching", "Reports", "API v3 | v2", "Use Cases"],
  },
];

export default function Footer() {
  return (
    <footer className="bg-[#191919] pt-12 pb-8 px-4 sm:px-8 lg:px-16">
      <div className="max-w-screen-xl mx-auto">
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-8">
          {footerColumns.map((col) => (
            <div key={col.title}>
              <h3 className="text-white font-bold text-lg md:text-xl mb-3">{col.title}</h3>
              <ul className="space-y-2">
                {col.links.map((link) => (
                  <li key={link}>
                    <Link
                      to="/"
                      className="text-white/70 hover:text-white text-sm md:text-base font-normal transition-colors"
                    >
                      {link}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        <div className="mt-10 pt-6 border-t border-white/10 text-center">
          <p className="text-white/40 text-sm">
            © {new Date().getFullYear()} AI Threat Lens. All rights reserved.
          </p>
        </div>
      </div>
    </footer>
  );
}
