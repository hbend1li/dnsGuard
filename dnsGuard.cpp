// Run it under /etc/dnsGuard

#include <iostream>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <cstdlib>
#include <array>
#include <stdexcept>
#include <unistd.h>

namespace fs = std::filesystem;

const std::string repo_path = "./AdguardFilters/";
const std::string rule_dir = "rules";
const std::string dnsmasq_rules = "/etc/dnsmasq.d/";

// Function to convert AdGuard rules to dnsmasq rules
void convert_to_dnsmasq_rules(const std::string &adguard_rule, std::ostream &output);

// Function to convert AdGuard rules to nftables rules
void open_adguard_rules(const std::string &filter_file, std::ostream &output);

int check_requirements(void);

int main()
{

  if (check_requirements() != 0){
    return 1;
  }

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
    try{
      fs::path target(dnsmasq_rules);
      fs::path link(rule_dir);
      fs::create_directory_symlink(target, link );
    }catch(const fs::filesystem_error &e){
      std::cerr << "Error creating directory -> " << e.what() << std::endl;
      return 1;
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
    std::cerr << "Error reading files in directory -> " << e.what() << std::endl;
    return 1;
  }

  // Parcourir chaque fichier de filtre
  for (const auto &filter_file : filter_files)
  {
    fs::path file_name(filter_file);
    std::string rule_file_name = rule_dir + "/" + file_name.stem().string() + ".conf";
    std::ofstream output_file(rule_file_name, std::ios::trunc);
    std::cout << rule_file_name << std::endl;
    open_adguard_rules(filter_file, output_file);
  }

  std::cout << "conversion is complete." << std::endl;
  return 0;
}

int is_process_running(const char *process_name) {
  char command[256];
  snprintf(command, sizeof(command), "pgrep -f '%s' > /dev/null", process_name);
  int result = system(command);
  return result == 0;
}

int check_requirements(void){
  if(0 != system("git --version  >nul 2>&1")){
    std::cerr << "git command not found, check if it's installed" << std::endl;
    return -1;
  }
  if(0 != system("dnsmasq --version  >nul 2>&1")){
    std::cerr << "dnsmasq command not found, check if it's installed." << std::endl;
    return -1;
  }
  if(!fs::exists(dnsmasq_rules)){
    std::cerr << dnsmasq_rules << " not found." << std::endl;
    return -1;
  }

  // Check running https server
  if(0 != is_process_running("busybox httpd -p 0.0.0.0:65321")){
    if (0 != system("busybox httpd -p 0.0.0.0:65321 -h /etc/dnsGuard/httpd")){
      std::cerr << "httpd: bind: Address already in use." << std::endl;
      return -1;
    }
  }
  return 0;
}

void convert_to_dnsmasq_rules(const std::string &adguard_rule, std::ostream &output)
{
  // Check that the AdGuard rule is valid
  if (adguard_rule.empty() || adguard_rule[0] == '!')
  {
    // Rule is empty or comment, ignore it
    return;
  }

  // Check if the rule starts with '||', which means a domain to block
  if (adguard_rule.find("||") == 0)
  {
    // Recover the domain to block by skiping the first characters (||)
    std::string domain = adguard_rule.substr(2);

    // Generate the corresponding dnsmasq rule and write it in the output stream
    output << "address=/" << domain << "/0.0.0.0:65321" << std::endl;
  }
}

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
