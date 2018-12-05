#include <elfio/elfio.hpp>
#include <iostream>
#include <stdio.h>
using namespace ELFIO;

extern "C" {
    void modify_elf(const char* binary_path, const char* output_path, int info_size, const char* info, int abbrev_size, const char* abbrev, int loc_size, const char* loc, int strtab_size, const char* strtab, int symtab_size, int symtab_entsize, int symtab_info, const char* symtab) {
        elfio f;
        f.load(binary_path);

        // for(int i=0; i<info_size; i++){
        //     printf("%.2x ", info[i] & 0x000000ff);
        // }
        // printf("\n");

        section* shstrtab;
        Elf_Half sec_num = f.sections.size();
        for(int i=0; i<sec_num; ++i){
            section* sec = f.sections[i];
            if (sec->get_name() == ".shstrtab"){
                shstrtab = sec;
            }
        }
        char debug_info_str[] = {'.', 'd', 'e', 'b', 'u', 'g', '_', 'i', 'n', 'f', 'o', 0};
        char debug_abbrev_str[] = {'.', 'd', 'e', 'b', 'u', 'g', '_', 'a', 'b', 'b', 'r', 'e', 'v', 0};
        char debug_loc_str[] = {'.', 'd', 'e', 'b', 'u', 'g', '_', 'l', 'o', 'c', 0};
        char symtab_str[] = {'.', 's', 'y', 'm', 't', 'a', 'b', 0};
        char strtab_str[] = {'.', 's', 't', 'r', 't', 'a', 'b', 0};
        shstrtab->append_data(debug_info_str, sizeof(debug_info_str));
        shstrtab->append_data(debug_abbrev_str, sizeof(debug_abbrev_str));
        shstrtab->append_data(debug_loc_str, sizeof(debug_loc_str));
        shstrtab->append_data(symtab_str, sizeof(symtab_str));
        shstrtab->append_data(strtab_str, sizeof(strtab_str));

        if (info_size > 0)
        {
            section* debug_info_sec = f.sections.add(".debug_info");
            debug_info_sec->set_type(SHT_PROGBITS);
            debug_info_sec->set_flags(0x0);
            debug_info_sec->set_info(0x0);
            debug_info_sec->set_link(0x0);
            debug_info_sec->set_addr_align(0x1);
            debug_info_sec->set_entry_size(0x0);
            debug_info_sec->set_address(0x0);
            debug_info_sec->set_data(info, info_size * sizeof(char));

            section* debug_abbrev_sec = f.sections.add(".debug_abbrev");
            debug_abbrev_sec->set_type(SHT_PROGBITS);
            debug_abbrev_sec->set_flags(0x0);
            debug_abbrev_sec->set_info(0x0);
            debug_abbrev_sec->set_link(0x0);
            debug_abbrev_sec->set_addr_align(0x1);
            debug_abbrev_sec->set_entry_size(0x0);
            debug_abbrev_sec->set_address(0x0);
            debug_abbrev_sec->set_data(abbrev, abbrev_size * sizeof(char));

            if(loc_size > 0)
            {
                section* debug_loc_sec = f.sections.add(".debug_loc");
                debug_loc_sec->set_type(SHT_PROGBITS);
                debug_loc_sec->set_flags(0x0);
                debug_loc_sec->set_info(0x0);
                debug_loc_sec->set_link(0x0);
                debug_loc_sec->set_addr_align(0x1);
                debug_loc_sec->set_entry_size(0x0);
                debug_loc_sec->set_address(0x0);
                debug_loc_sec->set_data(loc, loc_size * sizeof(char));
            }
        }

        if (symtab_size > 0)
        {
            section* symtab_sec = f.sections.add(".symtab");
            symtab_sec->set_type(SHT_SYMTAB);
            symtab_sec->set_flags(0x0);
            symtab_sec->set_addr_align(0x1);
            symtab_sec->set_entry_size(symtab_entsize);
            symtab_sec->set_address(0x0);
            symtab_sec->set_data(symtab, symtab_size * sizeof(char));

            section* strtab_sec = f.sections.add(".strtab");
            strtab_sec->set_type(SHT_STRTAB);
            strtab_sec->set_flags(0x0);
            strtab_sec->set_info(0x0);
            strtab_sec->set_link(0x0);
            strtab_sec->set_addr_align(0x1);
            strtab_sec->set_entry_size(0x0);
            strtab_sec->set_address(0x0);
            strtab_sec->set_data(strtab, strtab_size * sizeof(char));

            symtab_sec->set_link(strtab_sec->get_index());
            symtab_sec->set_info(symtab_info);
        }

        f.save(output_path);
    }
}
