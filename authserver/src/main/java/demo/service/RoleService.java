package demo.service;

import demo.model.Role;

public interface RoleService {

    Role findById(Long id);

    Role findByCode(String code);

}
