/*!
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
import { Box, chakra, Flex, Link } from "@chakra-ui/react";
import type { MouseEvent } from "react";
import { useTranslation } from "react-i18next";
import { FiChevronUp } from "react-icons/fi";
import { Link as RouterLink, useParams, useSearchParams } from "react-router-dom";

import { TaskName } from "src/components/TaskName";
import { useOpenGroups } from "src/context/openGroups";

import type { GridTask } from "./utils";

type Props = {
  depth?: number;
  nodes: Array<GridTask>;
};

const onMouseEnter = (event: MouseEvent<HTMLDivElement>) => {
  const tasks = document.querySelectorAll<HTMLDivElement>(`#${event.currentTarget.id}`);

  tasks.forEach((task) => {
    task.style.backgroundColor = "var(--chakra-colors-blue-subtle)";
  });
};

const onMouseLeave = (event: MouseEvent<HTMLDivElement>) => {
  const tasks = document.querySelectorAll<HTMLDivElement>(`#${event.currentTarget.id}`);

  tasks.forEach((task) => {
    task.style.backgroundColor = "";
  });
};

export const TaskNames = ({ nodes }: Props) => {
  const { t: translate } = useTranslation("dag");
  const { toggleGroupId } = useOpenGroups();
  const { dagId = "", groupId, taskId } = useParams();
  const [searchParams] = useSearchParams();

  return nodes.map((node) => (
    <Box
      bg={node.id === taskId || node.id === groupId ? "blue.muted" : undefined}
      borderBottomWidth={1}
      borderColor={node.isGroup ? "border.emphasized" : "border.muted"}
      id={node.id.replaceAll(".", "-")}
      key={node.id}
      maxHeight="20px"
      onMouseEnter={onMouseEnter}
      onMouseLeave={onMouseLeave}
      transition="background-color 0.2s"
    >
      {node.isGroup ? (
        <Flex alignItems="center">
          <Link asChild data-testid={node.id} display="inline">
            <RouterLink
              replace
              to={{
                pathname: `/dags/${dagId}/tasks/group/${node.id}`,
                search: searchParams.toString(),
              }}
            >
              <TaskName
                fontSize="sm"
                fontWeight="normal"
                isGroup={true}
                isMapped={Boolean(node.is_mapped)}
                label={node.label}
                paddingLeft={node.depth * 3 + 2}
                setupTeardownType={node.setup_teardown_type}
              />
            </RouterLink>
          </Link>
          <chakra.button
            aria-label={translate("grid.buttons.toggleGroup")}
            display="inline"
            height="20px"
            ml={1}
            onClick={() => toggleGroupId(node.id)}
            outlineColor="bg.inverted"
            px={1}
          >
            <FiChevronUp
              size="1rem"
              style={{
                transform: `rotate(${node.isOpen ? 0 : 180}deg)`,
                transition: "transform 0.5s",
              }}
            />
          </chakra.button>
        </Flex>
      ) : (
        <Link asChild data-testid={node.id} display="inline">
          <RouterLink
            replace
            to={{
              pathname: `/dags/${dagId}/tasks/${node.id}`,
              search: searchParams.toString(),
            }}
          >
            <TaskName
              fontSize="sm"
              fontWeight="normal"
              isMapped={Boolean(node.is_mapped)}
              label={node.label}
              paddingLeft={node.depth * 3 + 2}
              setupTeardownType={node.setup_teardown_type}
            />
          </RouterLink>
        </Link>
      )}
    </Box>
  ));
};
