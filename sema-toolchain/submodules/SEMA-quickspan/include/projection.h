#ifndef INCLUDE_PROJECTION_H
#define INCLUDE_PROJECTION_H

#include <graph.h>
#include <algorithm>
#include <iostream>

/** \defgroup Algorithm gspan
 *  @{
 */

/** @file projection.h
 * Header file containing the header of the class Projection.
 */


namespace quickspan {


    /**
     * New class of gspan.
     * It is used to not copy some data.
     */
    class Projection {
    public :

        /**
         * Constructor of Projection
         */
        Projection() {}

        /**
         * Overwrite operator [], return a const ref to the prev dfs at the index wanted
         * @param index The index
         * @return The const ref const ref to the prev dfs
         */
        const prev_dfs_t &operator[](size_t index) const {
            return projection[index];
        }

        /**
         * Add a prev dfs to the projection.
         * @param id The id of the graph containing the edge
         * @param edge The edge
         * @param prev The prev_dfs
         */
        void emplace_back(size_t id, const struct edge_t *edge, const struct prev_dfs_t *prev) {
            // VR: Construct a temp data
            prev_dfs_data data(id, edge);
            // VR: The threshold might have a small impact.
            if (projection.size() > 0) {
                // VR: Find if the data already exists.
                map<struct prev_dfs_data, const struct prev_dfs_data *>::const_iterator it = data_map.find(data);
                // VR: If not allocate a new one
                if (it == data_map.end()) {
                    const struct prev_dfs_data *data_p = new prev_dfs_data(data);
                    data_map[data] = data_p;
                    prev_dfs_t prev_dfs(prev, data_p);
                    projection.emplace_back(prev_dfs);

                }// VR: Else use the existing one.
                else {
                    prev_dfs_t prev_dfs(prev, it->second);
                    projection.emplace_back(prev_dfs);
                }
            } else {
                const struct prev_dfs_data *data_p = new prev_dfs_data(data);
                data_map[data] = data_p;
                prev_dfs_t prev_dfs(prev, data_p);
                projection.emplace_back(prev_dfs);
            }
        }

        /**
         * Free correctly the memory allocated for this projection.
         * Clear the projection and set its capacity to 0.
         */
        void clear() {
            map<struct prev_dfs_data, const struct prev_dfs_data *>::const_iterator it;
            for (it = data_map.begin(); it != data_map.end();) {
                delete it->second;
                it = data_map.erase(it);
            }
            projection.clear();
            projection.shrink_to_fit();
        }

        /**
         * Get the size of the projection
         * @return The size of the projection
         */
        size_t size() const {
            return projection.size();
        }

        /**
         * Destructor of Projection.
         */
        ~Projection() {
            this->clear();
        }

    private:
        /*!< Vector containing the projection */
        vector<struct prev_dfs_t> projection;

        /*!< Map containing the data and a pointer to them */
        map<struct prev_dfs_data, const struct prev_dfs_data *> data_map;
    };


}  // namespace quickspan


/** @} */

#endif //INCLUDE_PROJECTION_H
