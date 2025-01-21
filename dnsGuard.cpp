// Run it under /etc/dnsGuard

#include <array>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>

namespace fs = std::filesystem;

const std::string dnsguard_path = "/etc/dnsGuard/";
const std::string dnsmasq_path = "/etc/dnsmasq.d/";
const std::string AdguardFilters_dir = "AdguardFilters";
const std::string rule_dir = "rules";

// Function to convert AdGuard rules to dnsmasq rules
void convert_to_dnsmasq_rules(const std::string &adguard_rule,
                              std::ostream &output);

// Function to convert AdGuard rules to nftables rules
void open_adguard_rules(const std::string &filter_file, std::ostream &output);

int check_requirements(void);

int main()
{

  if (check_requirements() != 0)
  {
    return -1;
  }

  // git clone or git pull if exists
  if (!fs::exists(dnsguard_path + AdguardFilters_dir) ||
      !fs::is_directory(dnsguard_path + AdguardFilters_dir))
  {
    std::string command =
        "git clone https://github.com/AdguardTeam/AdguardFilters " +
        dnsguard_path + AdguardFilters_dir + " --depth=1";
    system(command.c_str());
  }
  else
  {
    // Move to the repository directory Perform a git pull
    fs::current_path(dnsguard_path + AdguardFilters_dir);
    system("git pull");
  }

  std::vector<std::string> filter_files;
  try
  {
    for (auto &entry :
         fs::recursive_directory_iterator(dnsguard_path + AdguardFilters_dir))
    {
      if (fs::is_regular_file(entry) && entry.path().extension() == ".txt")
      {
        filter_files.push_back(entry.path().string());
      }
    }
  }
  catch (const fs::filesystem_error &e)
  {
    std::cerr << "Error reading files in directory -> " << e.what()
              << std::endl;
    return 1;
  }

  // Iterate through each filter file
  for (const auto &filter_file : filter_files)
  {
    fs::path file_name(filter_file);
    std::string rule_file_name =
        dnsguard_path + rule_dir + "/" + file_name.stem().string() + ".conf";
    std::ofstream output_file(rule_file_name, std::ios::trunc);
    std::cout << rule_file_name << std::endl;
    open_adguard_rules(filter_file, output_file);
  }

  std::cout << "conversion is complete." << std::endl;
  return 0;
}

int is_process_running(const char *process_name)
{
    char command[256];
    snprintf(command, sizeof(command), "pgrep '%s' > /dev/null 2>&1", process_name);
    return system(command) == 0;
}

int check_requirements(void)
{
    if (0 != system("git --version > /dev/null 2>&1"))
    {
        std::cerr << "git command not found, check if it's installed" << std::endl;
        return -1;
    }
    if (0 != system("dnsmasq --version > /dev/null 2>&1"))
    {
        std::cerr << "dnsmasq command not found, check if it's installed." << std::endl;
        return -1;
    }
    if (!fs::exists(dnsmasq_path))
    {
        std::cerr << dnsmasq_path << " not found." << std::endl;
        return -1;
    }

    if (!fs::exists(dnsguard_path + rule_dir))
    {
        try
        {
            fs::path target(dnsmasq_path);
            fs::path link(dnsguard_path + rule_dir);
            fs::create_directory_symlink(target, link);
            std::cout << "Link created!" << std::endl;
        }
        catch (const fs::filesystem_error &e)
        {
            std::cerr << "Error creating directory -> " << e.what() << std::endl;

            return -1;
        }
    }

    if (!fs::exists(dnsguard_path)) {
        try {
            fs::create_directories(dnsguard_path);
        } catch (const fs::filesystem_error &e) {
            std::cerr << "Error creating dnsGuard directory -> " << e.what() << std::endl;
            return -1;
        }
    }

    if (!is_process_running("busybox httpd")) {
        if (0 != system("mkdir -p /etc/dnsGuard/httpd && busybox httpd -p 0.0.0.0:65321 -h /etc/dnsGuard/httpd"))
        {
            std::cerr << "Failed to start httpd server" << std::endl;
            return -1;
        }
    }
    return 0;
}

void convert_to_dnsmasq_rules(const std::string &adguard_rule,
                              std::ostream &output)
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

    // Remove any trailing modifiers or comments after the domain
    size_t pos = domain.find_first_of("^$#");
    if (pos != std::string::npos) {
        domain = domain.substr(0, pos);
    }
    
    // Skip if domain is empty or invalid
    if (!domain.empty() && domain.find('.') != std::string::npos) {
        output << "address=/" << domain << "/0.0.0.0" << std::endl;
    }
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
