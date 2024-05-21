#include <iostream>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <cstdlib>
#include <array>
#include <stdexcept>

namespace fs = std::filesystem;

// Function to convert AdGuard rules to dnsmasq rules
// Fonction pour convertir les règles AdGuard en règles dnsmasq
void convert_to_dnsmasq_rules(const std::string &adguard_rule, std::ostream &output)
{
  // Check that the AdGuard rule is valid
  // Vérifiez que la règle AdGuard est valide
  if (adguard_rule.empty() || adguard_rule[0] == '!')
  {
    // Rule is empty or comment, ignore it
    // La règle est vide ou un commentaire, ignorez-la
    return;
  }

  // Check if the rule starts with '||', which means a domain to block
  // Vérifiez si la règle commence par ||, ce qui signifie un domaine à bloquer
  if (adguard_rule.find("||") == 0)
  {
    // Récupérez le domaine à bloquer en sautant les premiers caractères (||)
    // Recover the domain to block by skiping the first characters (||)
    std::string domain = adguard_rule.substr(2);


    // Générez la règle dnsmasq correspondante et écrivez-la dans le flux de sortie
    // Generate the corresponding dnsmasq rule and write it in the output stream
    output << "address=/" << domain << "/0.0.0.0" << std::endl;
  }
}

// Fonction pour convertir les fichiers de filtre AdGuard en règles pour nftables
void open_adguard_rules(const std::string &filter_file, std::ostream &output)
{
  std::ifstream file(filter_file);
  if (!file.is_open())
  {
    std::cerr << "The file cannot be opened : " << filter_file << std::endl;
    return;
  }
  std::string line;
  while (std::getline(file, line))
  {
    convert_to_dnsmasq_rules(line, output);
  }
}

int main()
{
  const std::string repo_path = "./AdguardFilters/";
  const std::string rule_dir = "./rules/";

  // Vérifier si le répertoire du repository existe
  if (!fs::exists(repo_path) || !fs::is_directory(repo_path))
  {
    system("git clone https://github.com/AdguardTeam/AdguardFilters ./AdguardFilters --depth=1");
  }
  else
  {
    // Se déplacer dans le répertoire du repository Effectuer un git pull
    fs::current_path(repo_path);
    system("git pull");
    fs::current_path("../");
  }

  if (!fs::exists(rule_dir))
  {
    if (fs::create_directory(rule_dir))
    {
      std::cout << rule_dir << "directory created successfully." << std::endl;
    }
  }

  std::vector<std::string> filter_files;
  try
  {
    for (auto &entry : fs::recursive_directory_iterator(repo_path))
    {
      if (fs::is_regular_file(entry) && entry.path().extension() == ".txt")
      {
        filter_files.push_back(entry.path().string());
      }
    }
  }
  catch (const fs::filesystem_error &e)
  {
    std::cerr << "Error reading files in directory: " << e.what() << std::endl;
    return 1;
  }

  // Parcourir chaque fichier de filtre
  for (const auto &filter_file : filter_files)
  {
    std::filesystem::path file_name(filter_file);

    std::string rule_file_name = rule_dir + file_name.stem().string() + ".conf";
    std::ofstream output_file(rule_file_name, std::ios::trunc);

    std::cout << rule_file_name << std::endl;
    open_adguard_rules(filter_file, output_file);
  }

  std::cout << "conversion is complete." << std::endl;
  return 0;
}