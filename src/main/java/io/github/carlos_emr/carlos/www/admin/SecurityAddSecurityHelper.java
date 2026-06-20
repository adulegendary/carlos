/**
 * Copyright (c) 2001-2002. Department of Family Medicine, McMaster University. All Rights Reserved.
 * This software is published under the GPL GNU General Public License.
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * <p>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * <p>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 * <p>
 * This software was written for the
 * Department of Family Medicine
 * McMaster University
 * Hamilton
 * Ontario, Canada
 
 * <p>
 * Now maintained by the CARLOS EMR Project (2026+).
 * https://github.com/carlos-emr/carlos
 * CARLOS has no affiliation with OSCAR or McMaster University.
 */
package io.github.carlos_emr.carlos.www.admin;

import java.util.Date;

import jakarta.servlet.ServletRequest;
import jakarta.servlet.jsp.PageContext;

import io.github.carlos_emr.carlos.commn.dao.SecurityDao;
import io.github.carlos_emr.carlos.commn.model.Security;
import io.github.carlos_emr.carlos.managers.SecurityManager;
import io.github.carlos_emr.carlos.utility.SpringUtils;
import io.github.carlos_emr.carlos.daos.security.SecuserroleDao;  // the DAO (writes the table)
import io.github.carlos_emr.carlos.model.security.Secuserrole;    // the model (one role row)


import io.github.carlos_emr.MyDateFormat;
import io.github.carlos_emr.carlos.log.LogAction;
import io.github.carlos_emr.carlos.log.LogConst;
import io.github.carlos_emr.carlos.utility.LoggedInInfo;

/**
 * Helper class for securityaddsecurity.jsp page.
 */
public class SecurityAddSecurityHelper {

    private SecurityDao securityDao = SpringUtils.getBean(SecurityDao.class);
	private final SecurityManager securityManager = SpringUtils.getBean(SecurityManager.class);
    private final SecuserroleDao secUserRoleDao = SpringUtils.getBean(SecuserroleDao.class);
    // TODO(#2689): confirm from the maintainers (@yingbull).
    // Must be a role that grants "_appointment r". Placeholder until decided:
    private static final String DEFAULT_ROLE = "doctor";

    /**
     * Adds a sec record (i.e. user login information) for the providers.
     * <p/>
     * Processing status is available as a "message" variable.
     *
     * @param pageContext JSP page context
     */
    public void addProvider(PageContext pageContext) {
        String message = process(pageContext);
        pageContext.setAttribute("message", message);
    }

    private String process(PageContext pageContext) {
        ServletRequest request = pageContext.getRequest();

		String digestedPassword = this.securityManager.encodePassword(request.getParameter("password"));

        boolean isUserRecordAlreadyCreatedForProvider = !securityDao.findByProviderNo(request.getParameter("provider_no")).isEmpty();
        if (isUserRecordAlreadyCreatedForProvider) return "admin.securityaddsecurity.msgLoginAlreadyExistsForProvider";

        boolean isUserAlreadyExists = securityDao.findByUserName(request.getParameter("user_name")).size() > 0;
        if (isUserAlreadyExists) return "admin.securityaddsecurity.msgAdditionFailureDuplicate";

        Security s = new Security();
        s.setUserName(request.getParameter("user_name"));
        s.setPassword(digestedPassword);
        s.setProviderNo(request.getParameter("provider_no"));
        s.setPin(request.getParameter("pin"));
        s.setBExpireset(request.getParameter("b_ExpireSet") == null ? 0 : Integer.parseInt(request.getParameter("b_ExpireSet")));
        s.setDateExpiredate(MyDateFormat.getSysDate(request.getParameter("date_ExpireDate")));
        s.setBLocallockset(request.getParameter("b_LocalLockSet") == null ? 0 : Integer.parseInt(request.getParameter("b_LocalLockSet")));
        s.setBRemotelockset(request.getParameter("b_RemoteLockSet") == null ? 0 : Integer.parseInt(request.getParameter("b_RemoteLockSet")));

        if (request.getParameter("forcePasswordReset") != null && request.getParameter("forcePasswordReset").equals("1")) {
            s.setForcePasswordReset(Boolean.TRUE);
        } else {
            s.setForcePasswordReset(Boolean.FALSE);
        }

        s.setPasswordUpdateDate(new Date());
        s.setPinUpdateDate(new Date());

		if (request.getParameter("enableMfa") != null && request.getParameter("enableMfa").equals("1")) {
			s.setUsingMfa(Boolean.TRUE);
			s.setBLocallockset(0);
			s.setBRemotelockset(0);
		} else {
			s.setUsingMfa(Boolean.FALSE);
		}

        securityDao.persist(s);
        // Assign a default role so the new login has baseline privileges.
        // Without this the account authenticates but has no role, and the
        // schedule landing page fails its "_appointment r" check (issue #2689).
        Secuserrole role = new Secuserrole();
        role.setProviderNo(s.getProviderNo());
        role.setRoleName(DEFAULT_ROLE);
        role.setOrgcd("R0000001");
        role.setActiveyn(1);
        role.setLastUpdateDate(new Date());
        secUserRoleDao.save(role);


        LoggedInInfo loggedInInfo = LoggedInInfo.getLoggedInInfoFromSession(pageContext.getSession());
        LogAction.addLog(loggedInInfo != null ? loggedInInfo.getLoggedInProviderNo() : null, LogConst.ADD, LogConst.CON_SECURITY, request.getParameter("user_name"), request.getRemoteAddr());

        return "admin.securityaddsecurity.msgAdditionSuccess";
    }
}
