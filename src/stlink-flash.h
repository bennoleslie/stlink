int stlink_fwrite_flash(stlink_t *sl, const char *path, stm32_addr_t addr);
int stlink_write_flash(stlink_t* sl, stm32_addr_t address, uint8_t *data, unsigned length);
int stlink_erase_flash_mass(stlink_t* sl);
int stlink_fwrite_sram(stlink_t *sl, const char* path, stm32_addr_t addr);
int stlink_verify_write_flash(stlink_t *sl, stm32_addr_t address, uint8_t *data, unsigned length);
int stlink_erase_flash_page(stlink_t* sl, stm32_addr_t flashaddr);
uint32_t stlink_calculate_pagesize(stlink_t *sl, uint32_t flashaddr);
