package demo.service;

import demo.model.Role;
import demo.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(propagation = Propagation.SUPPORTS, readOnly = true)
public class RoleServiceBean implements RoleService{

    @Autowired
    private RoleRepository roleRepository;

    @Override
    public Role findById(Long id) {
        Role role = roleRepository.findOne(id);
        return role;
    }

    @Override
    public Role findByCode(String code) {
       return roleRepository.findByCode(code);
    }
}
